"""mc-antivpn-bench command line (runs inside the benchmark container).

  python3 -m bench run <family> [--products a,b] [--platforms x,y] [--run-id ID]
  python3 -m bench dataset build
  python3 -m bench pins

Families: functional (platforms, release, secrets), failure, performance, redis,
detection, all. Results: results/<run-id>/ (public, subject addresses replaced by
ids) and cache/private/runs/<run-id>/ (raw logs).
"""
import argparse
import asyncio
import datetime
import hashlib
import json
import os
import platform as host_platform
import subprocess
import sys
import time

from . import artifacts, engine, products, scenarios

ROOT = artifacts.ROOT
IPV4_ANY = __import__('re').compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
IPV6_ANY = __import__('re').compile(r'(?<![\w:])[0-9a-fA-F]{0,4}(?::[0-9a-fA-F]{0,4}){2,7}(?![\w:])')
# The candidate stays in the default set while its pull request is open.
ALL_PRODUCTS = ['connection-guard', 'connection-guard-candidate', 'foxgate', 'proxyshield', 'vpnguard']
ALL_PLATFORMS = ['paper', 'folia', 'velocity', 'bungee']


def address_forms(ip):
    """Every spelling an address appears in: canonical, exploded, and Java's (no leading zeros, all groups)."""
    import ipaddress
    address = ipaddress.ip_address(ip)
    if address.version == 4:
        return [ip]
    groups = address.exploded.split(':')
    return sorted({ip, address.compressed, address.exploded, ':'.join(g.lstrip('0') or '0' for g in groups)},
                  key=len, reverse=True)


def _mask(candidate, replacement):
    """Mask a real, non-loopback address; leave timestamps, versions and loopback alone."""
    import ipaddress
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    if address.is_loopback or address.is_unspecified or (address.version == 4 and candidate.count('.') != 3):
        return candidate
    if address.version == 6 and candidate.count(':') < 2:
        return candidate
    return replacement


class Recorder:
    def __init__(self, run_id):
        self.run_id = run_id
        self.public = os.path.join(ROOT, 'results', run_id)
        self.private = os.path.join(ROOT, 'cache', 'private', 'runs', run_id)
        os.makedirs(self.public, exist_ok=True)
        os.makedirs(self.private, exist_ok=True)
        self.subject_map = {}
        if os.path.exists(scenarios.PRIVATE):
            for line in open(scenarios.PRIVATE):
                item = json.loads(line)
                for form in address_forms(item['ip']):
                    self.subject_map[form] = f'<{item["id"]}>'
        self._sorted = sorted(self.subject_map, key=len, reverse=True)

    def redact(self, text):
        """Dataset addresses become their ids; every other non-loopback address becomes <ip>."""
        for ip in self._sorted:
            if ip in text:
                text = text.replace(ip, self.subject_map[ip])
        text = IPV4_ANY.sub(lambda m: _mask(m.group(0), '<ip>'), text)
        text = IPV6_ANY.sub(lambda m: _mask(m.group(0), '<ip6>'), text)
        return text

    def save(self, family, name, record):
        console = record.pop('_console', None)
        egress = record.pop('_egress', None)
        base = os.path.join(self.private, family)
        os.makedirs(base, exist_ok=True)
        if console is not None:
            open(os.path.join(base, name + '.console.log'), 'w').write(console)
        if egress is not None:
            with open(os.path.join(base, name + '.egress.jsonl'), 'w') as handle:
                for event in egress:
                    handle.write(json.dumps(event) + '\n')
        out = os.path.join(self.public, family)
        os.makedirs(out, exist_ok=True)
        text = self.redact(json.dumps(record, indent=2, sort_keys=True, default=str))
        open(os.path.join(out, name + '.json'), 'w').write(text + '\n')
        if console is not None:
            open(os.path.join(out, name + '.console.log'), 'w').write(self.redact(console))
        if egress is not None:
            with open(os.path.join(out, name + '.egress.jsonl'), 'w') as handle:
                for event in egress:
                    handle.write(self.redact(json.dumps(event)) + '\n')


def environment(canaries):
    def run(*command):
        try:
            return subprocess.run(command, capture_output=True, text=True, timeout=20).stdout.strip()
        except Exception:
            return None
    java = subprocess.run(['java', '-version'], capture_output=True, text=True).stderr.strip().splitlines()
    commit = run('git', '-C', ROOT, 'rev-parse', 'HEAD')
    dirty = run('git', '-C', ROOT, 'status', '--porcelain')
    return dict(
        started=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
        bench_commit=commit, bench_tree_dirty=bool(dirty), java=java, python=sys.version.split()[0],
        kernel=host_platform.release(), cpus=os.cpu_count(),
        memory_kb=int(open('/proc/meminfo').read().split()[1]) if os.path.exists('/proc/meminfo') else None,
        image=os.environ.get('BENCH_IMAGE'), host=os.environ.get('BENCH_HOST_DESCRIPTION'),
        keys_present=dict(proxycheck=bool(os.environ.get('PROXYCHECK_KEY')),
                          vpnapi=bool(os.environ.get('VPNAPI_KEY'))),
        canaries={k: hashlib.sha256(v.encode()).hexdigest()[:16] for k, v in canaries.items()},
        pins=products.pins(), artifacts_lock=json.load(open(artifacts.LOCK)) if os.path.exists(artifacts.LOCK) else {})


async def functional(runtime, recorder, canaries, product_ids, platforms):
    cases = scenarios.subjects(['tor', 'commercial_vpn', 'residential', 'mobile_cgnat'])
    positives = scenarios.subjects(['tor'], per_cohort=3, offset=1)
    negative = scenarios.subjects(['residential'], per_cohort=1, offset=1)[0]
    for product_id in product_ids:
        for platform in platforms:
            print(f'[functional] platform {product_id} {platform}', flush=True)
            recorder.save('platform', f'{product_id}-{platform}',
                          await scenarios.platform_parity(runtime, product_id, platform, canaries, cases))
            print(f'[functional] clean-install {product_id} {platform}', flush=True)
            recorder.save('clean-install', f'{product_id}-{platform}',
                          await scenarios.clean_install(runtime, product_id, platform, canaries, cases[:2]))
        for platform in [p for p in ('paper', 'velocity') if p in platforms]:
            print(f'[functional] upgrade/reload/secrets {product_id} {platform}', flush=True)
            recorder.save('upgrade', f'{product_id}-{platform}',
                          await scenarios.upgrade(runtime, product_id, platform, canaries, cases[:2]))
            recorder.save('invalid-reload', f'{product_id}-{platform}',
                          await scenarios.invalid_reload(runtime, product_id, platform, canaries, positives, negative))
            recorder.save('secrets', f'{product_id}-{platform}',
                          await scenarios.secret_leakage(runtime, product_id, platform, canaries, cases[:3]))


async def prebuild_templates(runtime, platforms):
    """Build every platform template once, with install egress (vanilla jar download)."""
    from . import servers
    runtime.install_mode()
    needed = [('paper', 'standalone')] + [('folia', 'standalone')] * ('folia' in platforms)
    needed += [('paper', f'{p}-backend') for p in ('velocity', 'bungee')]
    for platform, mode in needed:
        await servers.build_paper_template(platform, mode, engine.PRODUCT_PORT_BASE if mode == 'standalone'
                                           else engine.BACKEND_PORT)
    for proxy in ('velocity', 'bungee'):
        await servers.build_proxy_template(proxy, engine.PRODUCT_PORT_BASE, engine.BACKEND_PORT)
    runtime.rules(engine.measurement_rules())


async def main_run(args):
    from .runtime import Runtime
    run_id = args.run_id or datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    recorder = Recorder(run_id)
    canaries_path = os.path.join(engine.WORK, 'state', 'canaries.json')
    os.makedirs(os.path.dirname(canaries_path), exist_ok=True)
    if os.path.exists(canaries_path):
        canaries = json.load(open(canaries_path))
    else:
        canaries = engine.make_canaries()
        json.dump(canaries, open(canaries_path, 'w'))
    secrets_path = os.path.join(engine.WORK, 'state', 'secrets.json')
    json.dump(engine.secrets_spec(canaries), open(secrets_path, 'w'))
    runtime = Runtime(secrets_path).start()
    product_ids = args.products.split(',') if args.products else ALL_PRODUCTS
    platforms = args.platforms.split(',') if args.platforms else ALL_PLATFORMS
    manifest = dict(run_id=run_id, family=args.family, products=product_ids, platforms=platforms,
                    environment=environment(canaries))
    open(os.path.join(recorder.public, 'manifest.json'), 'w').write(json.dumps(manifest, indent=2, default=str))
    started = time.monotonic()
    try:
        await prebuild_templates(runtime, platforms)
        if args.family in ('functional', 'all'):
            await functional(runtime, recorder, canaries, product_ids, platforms)
        if args.family in ('failure', 'performance', 'redis', 'detection', 'all'):
            from . import heavy
            await heavy.run(args.family, runtime, recorder, canaries, product_ids, platforms)
    finally:
        runtime.stop()
        manifest['duration_s'] = time.monotonic() - started
        open(os.path.join(recorder.public, 'manifest.json'), 'w').write(json.dumps(manifest, indent=2, default=str))
    print(f'results: results/{run_id}', flush=True)


def main():
    parser = argparse.ArgumentParser(prog='bench')
    sub = parser.add_subparsers(dest='command', required=True)
    run = sub.add_parser('run')
    run.add_argument('family', choices=['functional', 'failure', 'performance', 'redis', 'detection', 'all'])
    run.add_argument('--products')
    run.add_argument('--platforms')
    run.add_argument('--run-id')
    sub.add_parser('pins')
    dataset = sub.add_parser('dataset')
    dataset.add_argument('action', choices=['build'])
    args = parser.parse_args()
    if args.command == 'run':
        asyncio.run(main_run(args))
    elif args.command == 'pins':
        from . import pins
        pins.main()
    elif args.command == 'dataset':
        from . import dataset
        dataset.build()


if __name__ == '__main__':
    main()
