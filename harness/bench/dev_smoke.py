"""Developer smoke test: one platform, no product, one ALLOW join."""
import asyncio
import sys

from . import mcclient, servers
from .runtime import Runtime


async def main(platform):
    runtime = Runtime().start()
    runtime.install_mode()
    if platform in ('paper', 'folia'):
        template = await servers.build_paper_template(platform, 'standalone', 25600)
        server = servers.Server(platform, servers.fresh_copy(template, '/work/run/smoke'), 25600)
        print('ready in', round(await server.start(), 1), 's')
        backend = None
    else:
        backend_template = await servers.build_paper_template('paper', f'{platform}-backend', 25601)
        backend = servers.Server('paper', servers.fresh_copy(backend_template, '/work/run/smoke-backend'), 25601)
        await backend.start()
        template = await servers.build_proxy_template(platform, 25600, 25601)
        server = servers.Server(platform, servers.fresh_copy(template, '/work/run/smoke'), 25600)
        print('ready in', round(await server.start(), 1), 's')
    try:
        print('status', await mcclient.status_protocol(25600))
        for ip in ('203.0.113.7', '2001:db8::7'):
            print(await mcclient.admit(25600, ip, 'Bench' + ip[-1], observe_s=3))
    finally:
        print('exit', await server.stop())
        if backend:
            await backend.stop()
        print('\n'.join(l for l in server.log_text().splitlines() if 'Bench' in l or 'WARN' in l or 'ERROR' in l)[-3000:])
        runtime.stop()


asyncio.run(main(sys.argv[1]))
