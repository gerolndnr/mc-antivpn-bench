"""Resolve the exact product versions under test to Modrinth files + SHA-512.

Run once when the version matrix changes; the output (products/modrinth-pins.json)
is committed and is the only source the runner downloads from.
"""
import json
import os
import sys
import urllib.request

from .artifacts import ROOT, USER_AGENT

MATRIX = {
    'connectionguard': ['0.5.0', '0.4.11'],
    'foxgate': ['1.2.0-pre10', '1.2.0-pre9'],
    'proxyshield': ['2.5.1+paper', '2.5.1+folia', '2.5.1+velocity', '2.5.1+bungee', '2.4.1+paper', '2.4.1+velocity'],
    'vpnguard': ['1.2.0', '1.1.1'],
}


def main():
    out = {}
    for project, wanted in MATRIX.items():
        request = urllib.request.Request(f'https://api.modrinth.com/v2/project/{project}/version',
                                         headers={'User-Agent': USER_AGENT})
        versions = json.load(urllib.request.urlopen(request, timeout=60))
        for number in wanted:
            match = [v for v in versions if v['version_number'] == number]
            if not match:
                sys.exit(f'{project} {number} is not published on Modrinth')
            version = match[0]
            file = next(f for f in version['files'] if f['primary'])
            out[f'{project}-{number}'] = dict(
                project=project, version=number, version_id=version['id'], version_type=version['version_type'],
                published=version['date_published'], loaders=sorted(version['loaders']),
                game_versions=version['game_versions'], url=file['url'], sha512=file['hashes']['sha512'],
                filename=file['filename'], size=file['size'])
    with open(os.path.join(ROOT, 'products', 'modrinth-pins.json'), 'w') as handle:
        json.dump(out, handle, indent=2, sort_keys=True)
        handle.write('\n')
    for key, value in out.items():
        print(key, value['version_type'], value['filename'], value['published'][:10])


if __name__ == '__main__':
    main()
