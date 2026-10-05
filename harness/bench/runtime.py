"""Container runtime: interposer process, egress guard and rule control."""
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.request

from . import netguard
from .interposer import CONTROL_PORT

STATE = os.environ.get('BENCH_STATE', '/work/state')

# Hosts a product or platform legitimately needs while *installing* (vanilla jar,
# libraries). Requests are logged like any other; they never count as provider calls.
INSTALL_HOSTS = ['piston-data.mojang.com', 'piston-meta.mojang.com', 'launchermeta.mojang.com',
                 'libraries.minecraft.net', 'repo.maven.apache.org', 'repo1.maven.org', '*.maven.apache.org',
                 'repo.papermc.io', 'oss.sonatype.org', 's01.oss.sonatype.org', 'maven.*', 'jitpack.io',
                 'repo.codemc.io', 'repo.codemc.org', 'github.com', 'objects.githubusercontent.com',
                 'raw.githubusercontent.com', 'release-assets.githubusercontent.com', 'api.modrinth.com',
                 'cdn.modrinth.com', 'repo.extendedclip.com', 'nexus.velocitypowered.com']
# Blocked in every phase, including installation: benchmark servers must never appear in any
# product's statistics (bStats, Sentry, Connection Guard Cloud).
TELEMETRY_HOSTS = ['bstats.org', '*.bstats.org', 'sentry.io', '*.sentry.io', 'api.connectionguard.net']


class Runtime:
    def __init__(self, secrets_path=None):
        self.secrets_path = secrets_path
        self.process = None

    def start(self):
        os.makedirs(STATE, exist_ok=True)
        args = [sys.executable, '-c', 'import sys; from bench.interposer import main; main(sys.argv[1], sys.argv[2] or None)',
                STATE, self.secrets_path or '']
        self.process = subprocess.Popen(args, cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                        stdout=open(os.path.join(STATE, 'interposer.log'), 'a'),
                                        stderr=subprocess.STDOUT)
        for _ in range(100):
            try:
                self.control('GET', '/health')
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError('interposer did not start')
        netguard.install(os.path.join(STATE, 'ca', 'ca.pem'))
        return self

    def control(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(f'http://127.0.0.1:{CONTROL_PORT}{path}', data=data, method=method)
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read())

    def rules(self, rules):
        rules = dict(rules)
        base = [dict(name='telemetry', hosts=TELEMETRY_HOSTS, action='deny')]
        rules['rules'] = base + list(rules.get('rules', []))
        return self.control('PUT', '/rules', rules)

    def install_mode(self):
        return self.rules(dict(default='passthrough', rules=[]))

    def sequence(self):
        return self.control('GET', '/stats')['sequence']

    def events_since(self, sequence):
        out = []
        with open(os.path.join(STATE, 'egress.jsonl')) as handle:
            for line in handle:
                event = json.loads(line)
                if event['seq'] > sequence:
                    out.append(event)
        return out

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait(10)
