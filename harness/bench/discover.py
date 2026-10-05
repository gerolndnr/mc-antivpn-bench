"""Discovery: start a product in its shipped state, observe files, logs and egress.

Used to write each product adapter from evidence rather than from documentation
alone. Output: /work/discovery/<pin>-<platform>/ (configs, console, egress).
"""
import asyncio
import json
import os
import shutil
import sys

from . import mcclient, products, servers
from .runtime import Runtime

PORT, BACKEND = 25600, 25601


async def discover(runtime, pin_key, platform, subject_ip):
    out = f'/work/discovery/{pin_key}-{platform}'
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out)
    backend = None
    if platform in ('paper', 'folia'):
        template = await servers.build_paper_template(platform, 'standalone', PORT)
    else:
        backend_template = await servers.build_paper_template('paper', f'{platform}-backend', BACKEND)
        backend = servers.Server('paper', servers.fresh_copy(backend_template, '/work/run/disc-backend'), BACKEND)
        await backend.start()
        template = await servers.build_proxy_template(platform, PORT, BACKEND)
    directory = servers.fresh_copy(template, '/work/run/disc')
    shutil.copy(products.jar(pin_key), os.path.join(directory, 'plugins', products.pins()[pin_key]['filename']))
    servers.chown(directory)
    mark = runtime.sequence()
    server = servers.Server(platform, directory, PORT)
    try:
        ready = await server.start()
        await asyncio.sleep(15)
        joins = [await mcclient.admit(PORT, subject_ip, 'Discover1', observe_s=10)]
        await asyncio.sleep(5)
        joins.append(await mcclient.admit(PORT, subject_ip, 'Discover2', observe_s=5))
    finally:
        code = await server.stop()
        if backend:
            await backend.stop()
    events = runtime.events_since(mark)
    with open(os.path.join(out, 'summary.json'), 'w') as handle:
        json.dump(dict(pin=pin_key, platform=platform, ready_s=ready, exit=code, joins=joins,
                       hosts=sorted({(e.get('host') or '?') + ':' + str(e.get('port')) + ' ' + str(e.get('action'))
                                     for e in events})), handle, indent=2)
    with open(os.path.join(out, 'egress.jsonl'), 'w') as handle:
        for event in events:
            handle.write(json.dumps(event) + '\n')
    shutil.copy(server.log_path, os.path.join(out, 'console.log'))
    shutil.copytree(os.path.join(directory, 'plugins'), os.path.join(out, 'plugins'),
                    ignore=shutil.ignore_patterns('*.jar', 'libs', 'lib', 'libraries'))
    print(json.dumps(dict(pin=pin_key, platform=platform, ready_s=round(ready, 1), exit=code,
                          joins=[(j['outcome'], j['reason'], round(j['total_ms'])) for j in joins],
                          egress=len(events)), indent=None))


async def main(pairs, subject_ip):
    runtime = Runtime().start()
    runtime.install_mode()
    try:
        for pair in pairs:
            pin_key, platform = pair.rsplit('@', 1)
            try:
                await discover(runtime, pin_key, platform, subject_ip)
            except Exception as error:  # keep going; the failure itself is evidence
                print(json.dumps(dict(pin=pin_key, platform=platform, error=f'{type(error).__name__}: {error}')))
    finally:
        runtime.stop()


if __name__ == '__main__':
    asyncio.run(main(sys.argv[2:], sys.argv[1]))
