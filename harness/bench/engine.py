"""Product instances: install once, then a fresh, profiled copy per case.

Life cycle of one case
  1. installed template  (platform template + product JAR, first start with open
     egress so the product can fetch its own libraries and write its defaults)
  2. fresh copy + profile edits (+ case edits such as Redis)
  3. start under measurement egress rules, wait for readiness:
     platform "Done" + the product's own readiness line (if it has one) + 5 s
     without new product console output or egress, capped at 180 s
  4. scenario steps
  5. stop, collect console/egress/files, verify the product JAR is unchanged
"""
import asyncio
import hashlib
import json
import os
import re
import secrets
import shutil
import time

import yaml

from . import products, servers

WORK = servers.WORK
INSTALLED = os.path.join(WORK, 'templates', 'installed')
PRODUCT_PORT_BASE = 25610
BACKEND_PORT = 25601

# Measurement-phase egress policy, identical for every product.
TELEMETRY = ['bstats.org', '*.bstats.org', 'sentry.io', '*.sentry.io', 'api.connectionguard.net']
# Self-updaters and version checks could change the artifact under test: blocked.
UPDATES = ['api.github.com', 'github.com', 'objects.githubusercontent.com', 'release-assets.githubusercontent.com',
           'hub.spigotmc.org', 'api.spiget.org', 'www.spigotmc.org', 'api.modrinth.com', 'cdn.modrinth.com',
           'piston-data.mojang.com', 'piston-meta.mojang.com', 'launchermeta.mojang.com', 'libraries.minecraft.net',
           'api.minecraftservices.com', 'sessionserver.mojang.com']
# Runtime library downloads (e.g. a Redis client loaded only when Redis is configured) are normal
# product behaviour on a server with internet access: streamed through, never recorded.
LIBRARIES = ['repo1.maven.org', 'repo.maven.apache.org', '*.maven.apache.org', 'repo.papermc.io', 'repo.okaeri.cloud',
             'jitpack.io', 'repo.codemc.io', 'oss.sonatype.org', 's01.oss.sonatype.org']
UPDATES_AND_LIBRARIES = UPDATES + LIBRARIES


def make_canaries(seed=None):
    """Format-compatible fake keys. Real keys never enter a product configuration."""
    rng = secrets.SystemRandom() if seed is None else __import__('random').Random(seed)
    digits = lambda n: ''.join(rng.choice('0123456789') for _ in range(n))
    hexs = lambda n: ''.join(rng.choice('0123456789abcdef') for _ in range(n))
    return dict(proxycheck=f'{digits(6)}-{digits(6)}-{digits(6)}-{digits(6)}', vpnapi=hexs(32))


def secrets_spec(canaries):
    return dict(proxycheck=dict(env='PROXYCHECK_KEY', canary=canaries['proxycheck'], hosts=['proxycheck.io']),
                vpnapi=dict(env='VPNAPI_KEY', canary=canaries['vpnapi'], hosts=['vpnapi.io']))


def measurement_rules(extra=None, default='record', normalize_quota=True):
    rules = [dict(name='telemetry', hosts=TELEMETRY, action='deny'),
             dict(name='updates', hosts=UPDATES, action='deny'),
             dict(name='libraries', hosts=LIBRARIES, action='passthrough')]
    rules += list(extra or [])
    if normalize_quota:
        # Keyless ProxyCheck allows 100 queries/day per egress address. The benchmark sends
        # far more than a real server's daily unique joins, so the fixture attaches the
        # operator's free key to keyless requests (when one is configured). The request the
        # product made, its cache key and the answer schema are unchanged.
        rules.append(dict(name='proxycheck-quota', hosts=['proxycheck.io'], action=default,
                          add_query_if_missing=dict(key='proxycheck')))
    return dict(default=default, rules=rules, replay_latency='recorded', seed=1)


def clean_install_rules():
    """A first start legitimately downloads libraries (and may check for updates)."""
    return dict(default='record', replay_latency='recorded', seed=1, rules=[
        dict(name='telemetry', hosts=TELEMETRY, action='deny'),
        dict(name='updates-and-libraries', hosts=UPDATES_AND_LIBRARIES, action='passthrough')])


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def set_path(data, dotted, value):
    keys = dotted.split('.')
    node = data
    for key in keys[:-1]:
        if not isinstance(node.get(key), dict):
            raise KeyError(f'{dotted}: "{key}" is not a mapping in the product configuration')
        node = node[key]
    if keys[-1] not in node:
        raise KeyError(f'{dotted}: key does not exist in the product configuration (adapter out of date?)')
    node[keys[-1]] = value


def substitute(value, canaries):
    if isinstance(value, str):
        return re.sub(r'\{canary:(\w+)\}', lambda m: canaries[m.group(1)], value)
    return value


def profile_edits(adapter, profile):
    chain = []
    while profile:
        spec = adapter['profiles'][profile]
        chain.insert(0, spec)
        profile = spec.get('extends')
    return [edit for spec in chain for edit in spec.get('edits', [])]


def apply_edits(data_dir, edits, canaries):
    for edit in edits:
        path = os.path.join(data_dir, edit['file'])
        with open(path) as handle:
            document = yaml.safe_load(handle) or {}
        for dotted, value in edit['set'].items():
            set_path(document, dotted, substitute(value, canaries))
        with open(path, 'w') as handle:
            yaml.safe_dump(document, handle, sort_keys=False, allow_unicode=True)


class Instance:
    def __init__(self, runtime, product_id, platform, slot=0, pin_key=None, label=None):
        self.runtime = runtime
        self.adapter = products.adapter(product_id)
        self.product_id, self.platform = product_id, platform
        self.pin_key = pin_key or self.adapter['pins'][platform]
        self.port = PRODUCT_PORT_BASE + slot
        self.slot = slot
        self.label = label or f'{product_id}-{platform}-{slot}'
        self.directory = os.path.join(WORK, 'run', self.label)
        self.server = None
        self.jar_name = products.pins()[self.pin_key]['filename']
        self.jar_sha256 = None
        self.mark = None
        self.history = []

    @property
    def data_dir(self):
        return os.path.join(self.directory, 'plugins', self.adapter['data_dir'][self.platform])

    # -------------------------------------------------------- templates
    async def platform_template(self):
        if self.platform in ('paper', 'folia'):
            return await servers.build_paper_template(self.platform, 'standalone', self.port)
        return await servers.build_proxy_template(self.platform, self.port, BACKEND_PORT)

    async def installed_template(self, clean=False):
        """First start of the product with open egress; cached per pin and platform."""
        target = os.path.join(INSTALLED, f'{self.pin_key}-{self.platform}')
        marker = os.path.join(target, '.installed.json')
        if os.path.exists(marker) and not clean:
            return target
        base = await self.platform_template()
        servers.fresh_copy(base, target)
        servers.set_port(target, self.platform, self.port)
        shutil.copy(products.jar(self.pin_key), os.path.join(target, 'plugins', self.jar_name))
        servers.chown(target)
        self.runtime.install_mode()
        server = servers.Server(self.platform, target, self.port, name=f'install-{self.label}')
        started = time.monotonic()
        ready = await server.start(timeout=300)
        await self.quiet(server, since_seq=None, cap=240)
        code = await server.stop()
        info = dict(pin=self.pin_key, platform=self.platform, ready_s=ready, install_s=time.monotonic() - started,
                    exit=code, built=time.time())
        for name in ('bench-console.log',):
            src = os.path.join(target, name)
            if os.path.exists(src):
                shutil.move(src, os.path.join(target, 'install-console.log'))
        shutil.rmtree(os.path.join(target, 'logs'), ignore_errors=True)
        with open(marker, 'w') as handle:
            json.dump(info, handle)
        servers.chown(target)
        return target

    # -------------------------------------------------------- readiness
    async def quiet(self, server, since_seq, cap=180, quiet_s=5.0):
        """Wait for the product's readiness line (if any), then for 5 s of silence."""
        deadline = time.monotonic() + cap
        pattern = self.adapter.get('ready_pattern')
        if pattern:
            if await server.wait_for(pattern, timeout=cap) is None:
                return dict(ready=False, reason=f'readiness line /{pattern}/ not seen within {cap}s')
        last_lines, last_seq, stable_since = -1, -1, time.monotonic()
        while time.monotonic() < deadline:
            lines = len(server.lines)
            seq = self.runtime.sequence()
            if lines != last_lines or seq != last_seq:
                last_lines, last_seq, stable_since = lines, seq, time.monotonic()
            elif time.monotonic() - stable_since >= quiet_s:
                return dict(ready=True)
            await asyncio.sleep(0.25)
        return dict(ready=True, reason=f'not quiet within {cap}s; continued')

    # -------------------------------------------------------- case
    async def prepare(self, profile, canaries, extra_edits=(), clean_install=False):
        if clean_install:
            base = await self.platform_template()
            servers.fresh_copy(base, self.directory)
            shutil.copy(products.jar(self.pin_key), os.path.join(self.directory, 'plugins', self.jar_name))
        else:
            servers.fresh_copy(await self.installed_template(), self.directory)
            apply_edits(self.data_dir, profile_edits(self.adapter, profile) + list(extra_edits), canaries)
        servers.set_port(self.directory, self.platform, self.port)
        servers.chown(self.directory)
        self.jar_sha256 = sha256_file(os.path.join(self.directory, 'plugins', self.jar_name))
        return self

    async def start(self, cap=180):
        if self.server:
            self.history.append(self.server.log_text())
        if self.mark is None:
            self.mark = self.runtime.sequence()
        self.server = servers.Server(self.platform, self.directory, self.port, name=self.label)
        started = time.monotonic()
        platform_ready = await self.server.start(timeout=300)
        readiness = await self.quiet(self.server, self.mark, cap=cap)
        return dict(platform_ready_s=platform_ready, ready_s=time.monotonic() - started, **readiness)

    async def command(self, text, settle=2.0):
        return await self.server.command(text, settle=settle)

    async def stop(self):
        code = await self.server.stop() if self.server else None
        jar = os.path.join(self.directory, 'plugins', self.jar_name)
        unchanged = os.path.exists(jar) and sha256_file(jar) == self.jar_sha256
        extra_jars = sorted(n for n in os.listdir(os.path.join(self.directory, 'plugins'))
                            if n.endswith('.jar') and n != self.jar_name)
        return dict(exit=code, jar_unchanged=unchanged, unexpected_plugin_jars=extra_jars)

    def egress(self):
        return self.runtime.events_since(self.mark or 0)

    def console(self):
        """Console of every start in this case, separated by a marker line."""
        parts = self.history + ([self.server.log_text()] if self.server else [])
        return '\n----- mc-antivpn-bench: server restarted -----\n'.join(parts)


class Backend:
    """Plain Paper backend (no product) behind a proxy under test."""

    def __init__(self, platform):
        self.platform = platform
        self.server = None

    async def start(self):
        template = await servers.build_paper_template('paper', f'{self.platform}-backend', BACKEND_PORT)
        directory = servers.fresh_copy(template, os.path.join(WORK, 'run', f'backend-{self.platform}'))
        self.server = servers.Server('paper', directory, BACKEND_PORT, name=f'backend-{self.platform}')
        await self.server.start(timeout=300)
        return self

    async def stop(self):
        if self.server:
            await self.server.stop()


ERROR_START = re.compile(r'(\[[0-9:]+ (ERROR|SEVERE)\]|\bERROR\]|\bSEVERE\]|^\S*Exception\b)')
CONTINUATION = re.compile(r'^(\s+at |\s*Caused by:|\s+\.\.\. \d+ more|\s*Suppressed:|[\w.$]+(Exception|Error)(:|$))')
PLATFORM_LOGGERS = ('PaperVersionFetcher', 'Error obtaining version information')


def product_errors(console, adapter, platform):
    """ERROR/SEVERE entries attributed to the product.

    An entry is the log line plus its stack-trace continuation lines. It is attributed
    when the product's logger tag, plugin name or a class from its package appears in
    that entry (never in neighbouring entries). Known platform-internal loggers are
    excluded.
    """
    tags = {t.lower() for t in (adapter['data_dir'][platform], adapter['id'], adapter['name'].split()[0],
                                 *adapter.get('packages', [])) if t}
    lines = console.splitlines()
    hits, index = [], 0
    while index < len(lines):
        line = lines[index]
        if ERROR_START.search(line) and not any(p in line for p in PLATFORM_LOGGERS):
            entry = [line]
            index += 1
            while index < len(lines) and CONTINUATION.match(lines[index]):
                entry.append(lines[index])
                index += 1
            text = '\n'.join(entry).lower()
            if any(tag in text for tag in tags):
                hits.append(line[:300])
            continue
        index += 1
    return hits
