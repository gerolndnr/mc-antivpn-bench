"""Test families that need no API keys: platforms, release quality, secret leakage.

Every function returns a JSON-serialisable record. Raw console and egress logs are
written next to it by the caller; records never contain real keys (the interposer
redacts) and never contain residential addresses (subjects are referenced by id).
"""
import asyncio
import json
import os
import re
import shutil

import yaml

from . import dataset
from . import mcclient
from . import products
from .pacing import observed, watch
from .engine import Backend, Instance, ProductNotLoaded, clean_install_rules, measurement_rules, product_errors, profile_edits

# The dataset version this run uses (BENCH_DATASET, else the newest v2 day, else v1); recorded in the manifest.
DATASET_VERSION = dataset.current()
PRIVATE = dataset.private_path(DATASET_VERSION)
OBSERVE_S = 8.0
_name_counter = [0]


def subjects(cohorts, per_cohort=1, offset=0):
    items = [json.loads(line) for line in open(PRIVATE)]
    out = []
    for cohort in cohorts:
        pool = [i for i in items if i['cohort'] == cohort]
        out += pool[offset:offset + per_cohort]
    return out


def player(prefix):
    _name_counter[0] += 1
    return f'{prefix[:6]}{_name_counter[0]:06d}'[:16]


def blocked(outcome):
    return outcome in ('DENY_LOGIN', 'DENY_CONFIG', 'DENY_PLAY')


async def join(instance, subject, observe_s=OBSERVE_S):
    # Learned per plugin for the whole run (bench/pacing.py); full window while calibrating and on every 10th join.
    window = watch(instance.product_id, observe_s)
    result = observed(instance.product_id, await mcclient.admit(instance.port, subject['ip'], player(instance.product_id),
                                                                observe_s=window), window)
    result.pop('subject_ip', None)
    result['subject'] = subject['id']
    result['label'] = subject['label']
    return result


async def with_instance(runtime, product_id, platform, profile, canaries, body, *, extra_edits=(), clean=False,
                        pin_key=None, label=None, keep=False, rules=None):
    """Run body(instance) between a fresh prepare/start and stop; always records teardown."""
    backend = None
    if platform in ('velocity', 'bungee'):
        backend = await Backend(platform).start()
    instance = Instance(runtime, product_id, platform, pin_key=pin_key, label=label)
    record = dict(product=product_id, platform=platform, profile=profile, pin=instance.pin_key)
    try:
        await instance.prepare(profile, canaries, extra_edits=extra_edits, clean_install=clean)
        runtime.rules(rules or measurement_rules())
        record['start'] = await instance.start()
        record['result'] = await body(instance)
    except ProductNotLoaded as error:
        record['not_loaded'] = True
        record['load_failure'] = True
        record['_install_console'] = str(error)
    except Exception as error:
        record['harness_error'] = f'{type(error).__name__}: {str(error)[:300]}'
    finally:
        record['stop'] = await instance.stop() if instance.server else None
        if backend:
            await backend.stop()
        console = instance.console() or record.pop('_install_console', '')
        record.pop('_install_console', None)
        record['product_error_lines'] = product_errors(console, instance.adapter, platform)[:40]
        name = re.escape(instance.adapter['data_dir'][platform])
        record['load_failure'] = record.get('load_failure') or bool(re.search(r"(Could not load plugin|Error loading plugin|Error occurred while enabling|Couldn't pass \w+ to)"
                                                r"[^\n]*(" + name + '|' + re.escape(instance.jar_name) + ')',
                                                console, re.I))
        record['egress_hosts'] = sorted({e.get('host') or '?' for e in instance.egress()})
        record['_console'] = console
        record['_egress'] = instance.egress()
        if not keep:
            shutil.rmtree(instance.directory, ignore_errors=True)
    return record


# ---------------------------------------------------------------- platforms
async def platform_parity(runtime, product_id, platform, canaries, cases):
    async def body(instance):
        return [await join(instance, subject) for subject in cases]
    return await with_instance(runtime, product_id, platform, 'enforce', canaries, body)


# ---------------------------------------------------------- release quality
async def clean_install(runtime, product_id, platform, canaries, cases):
    async def body(instance):
        data_dir = instance.data_dir
        generated = sorted(os.listdir(data_dir)) if os.path.isdir(data_dir) else []
        return dict(data_dir_created=os.path.isdir(data_dir), generated=generated[:40],
                    joins=[await join(instance, subject) for subject in cases])
    return await with_instance(runtime, product_id, platform, 'shipped', canaries, body, clean=True,
                               label=f'clean-{product_id}-{platform}', rules=clean_install_rules())


# One operator-changed integer per product; the first path that exists in the *previous*
# release's generated config is used and bumped by one.
UPGRADE_MARKERS = {
    'connection-guard': ['lookup.http-timeout-ms', 'provider.cache.expiration.vpn', 'required-positive-flags'],
    'connection-guard-candidate': ['lookup.http-timeout-ms', 'provider.cache.expiration.vpn', 'required-positive-flags'],
    'connection-guard-061': ['lookup.http-timeout-ms', 'provider.cache.expiration.vpn', 'required-positive-flags'],
    'foxgate': ['antivpn.timeout', 'antivpn.maxFlags'],
    'proxyshield': ['api.timeout-seconds', 'api.cache-minutes'],
    'vpnguard': ['timeout', 'cache-ttl-hours'],
    # KauriVPN's only integer setting; with its default H2 database the port is not used.
    'kaurivpn': ['database.port'],
    'advancedantivpn': ['Cache Time', 'Concurrent Connections Per IP.Maximum Amount'],
}


def read_path(document, dotted):
    node = document
    for key in dotted.split('.'):
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


async def upgrade(runtime, product_id, platform, canaries, cases):
    """Previous release with one operator-changed value -> current JAR, same data folder."""
    from . import servers
    adapter = products.adapter(product_id)
    previous = adapter.get('previous_pins', {}).get(platform)
    if not previous:
        return dict(product=product_id, platform=platform, applicable=False, reason='no previous release pinned')
    old = Instance(runtime, product_id, platform, pin_key=previous, label=f'upgrade-{product_id}-{platform}')
    record = dict(product=product_id, platform=platform, from_pin=previous, to_pin=adapter['pins'][platform])
    try:
        await old.prepare('shipped', canaries)
    except Exception as error:
        record['harness_error'] = f'previous release could not be installed: {error}'
        return record
    path = os.path.join(old.data_dir, adapter['config'])
    document = yaml.safe_load(open(path)) or {}
    dotted = next((p for p in UPGRADE_MARKERS.get(product_id, []) if isinstance(read_path(document, p), int)
                   and not isinstance(read_path(document, p), bool)), None)
    marker_set = dotted is not None
    value = read_path(document, dotted) + 1 if marker_set else None
    if marker_set:
        node = document
        keys = dotted.split('.')
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
        yaml.safe_dump(document, open(path, 'w'), sort_keys=False, allow_unicode=True)
    # Swap the JAR in place: what an operator does when updating.
    os.remove(os.path.join(old.directory, 'plugins', old.jar_name))
    current_pin = adapter['pins'][platform]
    import shutil
    current_name = products.pins()[current_pin]['filename']
    shutil.copy(products.jar(current_pin), os.path.join(old.directory, 'plugins', current_name))
    servers.chown(old.directory)
    instance = old
    instance.pin_key, instance.jar_name = current_pin, current_name
    from .engine import sha256_file
    instance.jar_sha256 = sha256_file(os.path.join(instance.directory, 'plugins', current_name))
    backend = await Backend(platform).start() if platform in ('velocity', 'bungee') else None
    try:
        runtime.rules(measurement_rules())
        record['start'] = await instance.start()
        record['joins'] = [await join(instance, subject) for subject in cases]
        after = yaml.safe_load(open(path)) or {}
        record['marker'] = dict(path=dotted, set_before=marker_set, expected=value, after=read_path(after, dotted))
        record['marker_preserved'] = marker_set and read_path(after, dotted) == value
    except Exception as error:
        record['harness_error'] = f'{type(error).__name__}: {str(error)[:300]}'
    finally:
        record['stop'] = await instance.stop() if instance.server else None
        if backend:
            await backend.stop()
        console = instance.console()
        record['product_error_lines'] = product_errors(console, instance.adapter, platform)[:40]
        record['_console'] = console
        shutil.rmtree(instance.directory, ignore_errors=True)
    return record


BROKEN_YAML = '\nthis-is: [not, closed\n  - broken: "yaml\n'


async def invalid_reload(runtime, product_id, platform, canaries, positives, negative):
    """Reload with a syntactically broken config: protection must survive, error must be visible."""
    async def body(instance):
        out = dict(before=await join(instance, positives[0]))
        config = os.path.join(instance.data_dir, instance.adapter['config'])
        original = open(config).read()
        with open(config, 'a') as handle:
            handle.write(BROKEN_YAML)
        mark = len(instance.server.lines)
        out['reload_output'] = (await instance.command(instance.adapter['commands']['reload'], settle=4.0))[:30]
        out['after_positive'] = await join(instance, positives[1])
        out['after_negative'] = await join(instance, negative)
        out['process_alive'] = instance.server.process.returncode is None
        out['error_reported'] = any(re.search(r'(?i)(error|invalid|failed|could not|exception|yaml|reject)', line)
                                    for _, line in instance.server.lines[mark:])
        with open(config, 'w') as handle:
            handle.write(original)
        out['restore_output'] = (await instance.command(instance.adapter['commands']['reload'], settle=4.0))[:30]
        out['after_restore_positive'] = await join(instance, positives[2])
        return out
    return await with_instance(runtime, product_id, platform, 'enforce', canaries, body,
                               label=f'reload-{product_id}-{platform}')


# ------------------------------------------------------------- secret leakage
async def secret_leakage(runtime, product_id, platform, canaries, cases):
    """Free-key profile with canary keys; scan logs, files and egress for the canaries."""
    async def body(instance):
        joins = [await join(instance, subject) for subject in cases]
        outputs = {}
        for command in instance.adapter['commands'].get('inspect', []):
            outputs[command] = (await instance.command(command, settle=2.0))[:40]
        await instance.command(instance.adapter['commands']['reload'], settle=4.0)
        joins.append(await join(instance, cases[0]))
        return dict(joins=joins, command_lines=sum(len(v) for v in outputs.values()))
    record = await with_instance(runtime, product_id, platform, 'free_keys', canaries, body,
                                 label=f'secrets-{product_id}-{platform}', keep=True)
    instance_dir = os.path.join('/work/run', f'secrets-{product_id}-{platform}')
    findings = []
    console = record.get('_console', '')
    for name, canary in canaries.items():
        if canary in console:
            lines = [line for line in console.splitlines() if canary in line]
            findings.append(dict(kind='console', secret=name, count=len(lines),
                                 example=lines[0].replace(canary, f'<CANARY:{name}>')[:240]))
    adapter = products.adapter(product_id)
    data_dir = os.path.join(instance_dir, 'plugins', adapter['data_dir'][platform])
    configured = {os.path.normpath(os.path.join(data_dir, edit['file']))
                  for edit in profile_edits(adapter, 'free_keys')}
    for root, _, files in os.walk(instance_dir):
        for filename in files:
            path = os.path.join(root, filename)
            if os.path.normpath(path) in configured or filename.endswith('.jar'):
                continue
            try:
                data = open(path, 'rb').read()
            except OSError:
                continue
            for name, canary in canaries.items():
                if canary.encode() in data:
                    findings.append(dict(kind='file', secret=name, path=os.path.relpath(path, instance_dir),
                                         mode=oct(os.stat(path).st_mode & 0o777)))
    for event in record.get('_egress', []):
        for leak in event.get('leaks') or []:
            if not leak['allowed_host']:
                findings.append(dict(kind='egress_foreign_host', secret=leak['secret'], host=event.get('host')))
            elif not leak['tls']:
                findings.append(dict(kind='egress_plaintext', secret=leak['secret'], host=event.get('host')))
    config_modes = {}
    for path in configured:
        if os.path.exists(path):
            config_modes[os.path.relpath(path, instance_dir)] = oct(os.stat(path).st_mode & 0o777)
    record['findings'] = findings
    record['configured_key_files'] = config_modes
    shutil.rmtree(instance_dir, ignore_errors=True)
    return record
