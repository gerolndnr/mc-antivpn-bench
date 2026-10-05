"""Server fixtures: pinned platforms, identical settings, one product at a time.

Topologies
  paper     Paper 1.21.11 standalone, PROXY protocol on its listener
  folia     Folia 1.21.11 standalone, PROXY protocol on its listener
  velocity  Velocity 3.5.1 (product here) -> Paper backend (no product), modern forwarding
  bungee    BungeeCord (product here) -> Paper backend (no product), legacy forwarding

Fixture-wide settings that would otherwise act *before* the product and mask its
behaviour are disabled identically for every product and documented in
METHODOLOGY.md: platform connection throttles / login rate limits (the same-IP
stampede must reach the product), bStats (benchmarks must not inflate anyone's
public statistics) and update checks where the platform has them.
"""
import asyncio
import json
import os
import re
import shutil
import subprocess
import time

import yaml

from . import artifacts

ROOT = artifacts.ROOT
WORK = os.environ.get('BENCH_WORK', '/work')
TEMPLATES = os.path.join(WORK, 'templates')
MC_UID = 1001
ANSI = re.compile(r'\x1b\[[0-9;]*[A-Za-z]|\[m')
# Real provider keys live only in the interposer process, never in a product JVM.
SECRET_ENV = ('PROXYCHECK_KEY', 'VPNAPI_KEY')
FORWARDING_SECRET = 'mc-antivpn-bench-forwarding-secret'

PLATFORMS = {
    'paper': dict(id='paper-1.21.11-132', filename='paper-1.21.11-132.jar',
                  url='https://fill-data.papermc.io/v1/objects/5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba/paper-1.21.11-132.jar',
                  sha256='5ffef465eeeb5f2a3c23a24419d97c51afd7dbb4923ff42df9a3f58bba1ccfba'),
    'folia': dict(id='folia-1.21.11-14', filename='folia-1.21.11-14.jar',
                  url='https://fill-data.papermc.io/v1/objects/f52c408490a0225611e67907a3ca19f7e6da2c6bc899e715d5f46844e7103c39/folia-1.21.11-14.jar',
                  sha256='f52c408490a0225611e67907a3ca19f7e6da2c6bc899e715d5f46844e7103c39'),
    'velocity': dict(id='velocity-3.5.1-615', filename='velocity-3.5.1-615.jar',
                     url='https://fill-data.papermc.io/v1/objects/b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3/velocity-3.5.1-615.jar',
                     sha256='b4e3164df5377346854dc6cb9e6a78022b1946ff69e89676313f5f6f1c6f0fb3'),
    'bungee': dict(id='bungeecord-2102', filename='BungeeCord-2102.jar',
                   url='https://hub.spigotmc.org/jenkins/job/BungeeCord/2102/artifact/bootstrap/target/BungeeCord.jar'),
}
READY = {
    'paper': re.compile(r'Done \(\d'), 'folia': re.compile(r'Done \(\d'),
    'velocity': re.compile(r'Done \(\d'), 'bungee': re.compile(r'Listening on /'),
}
HEAP = {'paper': '1G', 'folia': '1G', 'velocity': '512M', 'bungee': '512M'}
JVM_FLAGS = ['-XX:+UseG1GC', '-Dfile.encoding=UTF-8', '-Dterminal.jline=false', '-Dterminal.ansi=false',
             '-Djline.terminal=jline.UnsupportedTerminal', '-Dpaper.playerconnection.keepalive=60',
             '-DIReallyKnowWhatIAmDoingISwear=true']


def platform_jar(platform):
    entry = PLATFORMS[platform]
    if entry.get('sha256'):
        return artifacts.fetch(entry)
    return artifacts.lock_unpublished(entry)


def chown(path):
    # -P: never follow the shared read-only symlinks back into a template
    subprocess.run(['chown', '-R', '-P', f'{MC_UID}:{MC_UID}', path], check=True)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as handle:
        handle.write(text)


def load_yaml(path):
    with open(path) as handle:
        return yaml.safe_load(handle) or {}


def dump_yaml(path, data):
    with open(path, 'w') as handle:
        yaml.safe_dump(data, handle, sort_keys=False, allow_unicode=True)


def set_path(data, dotted, value):
    keys = dotted.split('.')
    node = data
    for key in keys[:-1]:
        if not isinstance(node.get(key), dict):
            node[key] = {}
        node = node[key]
    node[keys[-1]] = value


class Server:
    """One JVM process with a console on stdin and a captured log."""

    def __init__(self, platform, directory, port, name=None):
        self.platform, self.directory, self.port = platform, directory, port
        self.name = name or platform
        self.process = None
        self.lines = []
        self.log_path = os.path.join(directory, 'bench-console.log')
        self.reader_task = None
        self.started_at = None

    async def start(self, timeout=240):
        jar = os.path.join(self.directory, 'server.jar')
        command = ['setpriv', f'--reuid={MC_UID}', f'--regid={MC_UID}', '--init-groups', '--',
                   'java', f'-Xms{HEAP[self.platform]}', f'-Xmx{HEAP[self.platform]}', *JVM_FLAGS, '-jar', jar]
        if self.platform in ('paper', 'folia'):
            command.append('--nogui')
        self.started_at = time.monotonic()
        self.process = await asyncio.create_subprocess_exec(
            *command, cwd=self.directory, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT, env={**{k: v for k, v in os.environ.items() if k not in SECRET_ENV}, 'HOME': '/home/mc', 'TERM': 'dumb'})
        log = open(self.log_path, 'a', buffering=1)
        ready = asyncio.get_running_loop().create_future()

        async def pump():
            while True:
                line = await self.process.stdout.readline()
                if not line:
                    break
                text = ANSI.sub('', line.decode('utf-8', 'replace').rstrip('\n'))
                self.lines.append((time.monotonic(), text))
                log.write(text + '\n')
                if not ready.done() and READY[self.platform].search(text):
                    ready.set_result(time.monotonic() - self.started_at)
            log.close()
            if not ready.done():
                ready.set_exception(RuntimeError(f'{self.name} exited before ready'))
        self.reader_task = asyncio.create_task(pump())
        return await asyncio.wait_for(ready, timeout)

    async def command(self, text, settle=1.0):
        mark = len(self.lines)
        self.process.stdin.write((text + '\n').encode())
        await self.process.stdin.drain()
        await asyncio.sleep(settle)
        return [line for _, line in self.lines[mark:]]

    async def wait_for(self, pattern, timeout=30, since=0):
        deadline = time.monotonic() + timeout
        regex = re.compile(pattern)
        while time.monotonic() < deadline:
            for _, line in self.lines[since:]:
                if regex.search(line):
                    return line
            await asyncio.sleep(0.1)
        return None

    async def stop(self, timeout=60):
        if not self.process or self.process.returncode is not None:
            return self.process.returncode if self.process else None
        try:
            stop = 'end' if self.platform == 'bungee' else 'shutdown' if self.platform == 'velocity' else 'stop'
            self.process.stdin.write((stop + '\n').encode())
            await self.process.stdin.drain()
            await asyncio.wait_for(self.process.wait(), timeout)
        except (asyncio.TimeoutError, ConnectionError, BrokenPipeError):
            self.process.kill()
            await self.process.wait()
        if self.reader_task:
            await asyncio.wait_for(self.reader_task, 10)
        return self.process.returncode

    def log_text(self):
        return '\n'.join(line for _, line in self.lines)


# ------------------------------------------------------------------ templates
def _bstats_off(directory, platform):
    if platform == 'velocity':
        write(os.path.join(directory, 'plugins', 'bStats', 'config.txt'),
              'enabled=false\nserver-uuid=00000000-0000-4000-8000-000000000000\nlog-errors=false\n'
              'log-sent-data=false\nlog-response-status-text=false\n')
    else:
        write(os.path.join(directory, 'plugins', 'bStats', 'config.yml'),
              'enabled: false\nserverUuid: 00000000-0000-4000-8000-000000000000\nlogFailedRequests: false\n'
              'logSentData: false\nlogResponseStatusText: false\n')


def _paper_properties(port):
    return '\n'.join([
        'online-mode=false', f'server-port={port}', 'server-ip=127.0.0.1', 'level-type=minecraft\\:flat',
        'generate-structures=false', 'spawn-protection=0', 'max-players=5000', 'view-distance=2',
        'simulation-distance=2', 'enable-rcon=false', 'enable-query=false', 'sync-chunk-writes=false',
        'allow-nether=false', 'motd=mc-antivpn-bench', 'enforce-secure-profile=false',
        'network-compression-threshold=256', 'spawn-monsters=false', 'spawn-animals=false', 'pvp=false',
        'player-idle-timeout=0', 'prevent-proxy-connections=false', 'log-ips=true', '']) + '\n'


async def build_paper_template(platform, mode, port):
    """mode: standalone (PROXY protocol on) | velocity-backend | bungee-backend."""
    target = os.path.join(TEMPLATES, f'{platform}-{mode}')
    marker = os.path.join(target, '.template-ready')
    if os.path.exists(marker):
        return target
    shutil.rmtree(target, ignore_errors=True)
    os.makedirs(target)
    shutil.copy(platform_jar(platform), os.path.join(target, 'server.jar'))
    write(os.path.join(target, 'eula.txt'), 'eula=true\n')
    write(os.path.join(target, 'server.properties'), _paper_properties(port))
    _bstats_off(target, platform)
    chown(target)
    server = Server(platform, target, port, name=f'template-{platform}')
    await server.start(timeout=600)
    await server.stop()
    bukkit = load_yaml(os.path.join(target, 'bukkit.yml'))
    set_path(bukkit, 'settings.connection-throttle', -1)
    dump_yaml(os.path.join(target, 'bukkit.yml'), bukkit)
    spigot = load_yaml(os.path.join(target, 'spigot.yml'))
    set_path(spigot, 'settings.bungeecord', mode == 'bungee-backend')
    dump_yaml(os.path.join(target, 'spigot.yml'), spigot)
    global_path = os.path.join(target, 'config', 'paper-global.yml')
    paper = load_yaml(global_path)
    set_path(paper, 'proxies.proxy-protocol', mode == 'standalone')
    set_path(paper, 'proxies.velocity.enabled', mode == 'velocity-backend')
    set_path(paper, 'proxies.velocity.online-mode', False)
    set_path(paper, 'proxies.velocity.secret', FORWARDING_SECRET)
    set_path(paper, 'proxies.bungee-cord.online-mode', False)
    dump_yaml(global_path, paper)
    for name in ('bench-console.log',):
        try:
            os.remove(os.path.join(target, name))
        except FileNotFoundError:
            pass
    shutil.rmtree(os.path.join(target, 'logs'), ignore_errors=True)
    write(marker, json.dumps(dict(platform=platform, mode=mode, built=time.time())))
    chown(target)
    return target


async def build_proxy_template(platform, port, backend_port):
    target = os.path.join(TEMPLATES, platform)
    marker = os.path.join(target, '.template-ready')
    if os.path.exists(marker):
        return target
    shutil.rmtree(target, ignore_errors=True)
    os.makedirs(target)
    shutil.copy(platform_jar(platform), os.path.join(target, 'server.jar'))
    _bstats_off(target, platform)
    chown(target)
    server = Server(platform, target, port, name=f'template-{platform}')
    await server.start(timeout=300)
    await server.stop()
    if platform == 'velocity':
        path = os.path.join(target, 'velocity.toml')
        with open(path) as handle:
            toml = handle.read()
        replacements = {
            r'^bind = .*$': f'bind = "127.0.0.1:{port}"',
            r'^online-mode = .*$': 'online-mode = false',
            r'^force-key-authentication = .*$': 'force-key-authentication = false',
            r'^player-info-forwarding-mode = .*$': 'player-info-forwarding-mode = "modern"',
            r'^haproxy-protocol = .*$': 'haproxy-protocol = true',
            r'^login-ratelimit = .*$': 'login-ratelimit = 0',
            r'^show-ping-requests = .*$': 'show-ping-requests = false',
            r'^log-player-connections = .*$': 'log-player-connections = true',
        }
        for pattern, value in replacements.items():
            toml, count = re.subn(pattern, value, toml, flags=re.M)
            if count != 1:
                raise RuntimeError(f'velocity.toml: expected one match for {pattern}, got {count}')
        toml = re.sub(r'(?ms)^\[servers\].*?(?=^\[forced-hosts\])',
                      f'[servers]\nlobby = "127.0.0.1:{backend_port}"\ntry = ["lobby"]\n\n', toml)
        toml = re.sub(r'(?ms)^\[forced-hosts\].*?(?=^\[advanced\])', '[forced-hosts]\n\n', toml)
        with open(path, 'w') as handle:
            handle.write(toml)
        write(os.path.join(target, 'forwarding.secret'), FORWARDING_SECRET)
    else:
        path = os.path.join(target, 'config.yml')
        config = load_yaml(path)
        config['online_mode'] = False
        config['ip_forward'] = True
        config['connection_throttle'] = -1
        config['log_pings'] = False
        listener = config['listeners'][0]
        listener['host'] = f'127.0.0.1:{port}'
        listener['proxy_protocol'] = True
        listener['priorities'] = ['lobby']
        listener['query_enabled'] = False
        config['servers'] = {'lobby': dict(motd='backend', address=f'127.0.0.1:{backend_port}', restricted=False)}
        dump_yaml(path, config)
    try:
        os.remove(os.path.join(target, 'bench-console.log'))
    except FileNotFoundError:
        pass
    shutil.rmtree(os.path.join(target, 'logs'), ignore_errors=True)
    write(marker, json.dumps(dict(platform=platform, built=time.time())))
    chown(target)
    return target


def set_port(directory, platform, port):
    """Point a copied server at its own port (templates are port-independent)."""
    if platform in ('paper', 'folia'):
        path = os.path.join(directory, 'server.properties')
        with open(path) as handle:
            text = re.sub(r'(?m)^server-port=.*$', f'server-port={port}', handle.read())
        with open(path, 'w') as handle:
            handle.write(text)
    elif platform == 'velocity':
        path = os.path.join(directory, 'velocity.toml')
        with open(path) as handle:
            text = re.sub(r'(?m)^bind = .*$', f'bind = "127.0.0.1:{port}"', handle.read())
        with open(path, 'w') as handle:
            handle.write(text)
    else:
        path = os.path.join(directory, 'config.yml')
        config = load_yaml(path)
        config['listeners'][0]['host'] = f'127.0.0.1:{port}'
        dump_yaml(path, config)


# Read-only after the template's first start; shared by symlink to keep each case small.
SHARED_DIRS = ('libraries', 'cache', 'versions')


def fresh_copy(template, destination):
    shutil.rmtree(destination, ignore_errors=True)
    shared = [name for name in SHARED_DIRS if os.path.isdir(os.path.join(template, name))
              and not os.path.islink(os.path.join(template, name))]
    shutil.copytree(template, destination, symlinks=True,
                    ignore=lambda directory, names: [n for n in names if directory == template and n in shared])
    for name in shared:
        source = os.path.join(template, name)
        subprocess.run(['chown', '-R', '0:0', source], check=True)
        subprocess.run(['chmod', '-R', 'a+rX,go-w', source], check=True)
        os.symlink(source, os.path.join(destination, name))
    try:
        os.remove(os.path.join(destination, '.template-ready'))
    except FileNotFoundError:
        pass
    chown(destination)
    return destination
