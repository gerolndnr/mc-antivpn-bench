"""The overview for the README: the newest complete result of every family, from this repository's workflow runs.

  GH_TOKEN=... python3 -m bench.latest --repo gerolndnr/mc-antivpn-bench --output docs/overview

Picks, newest first among successful `benchmark` runs started by hand or by the schedule:
  - per family (functional, failure, redis, detection, performance on Velocity, providers) the newest run that
    compared at least two products (providers: any run);
  - for detection, a nightly chunk only together with the other chunks of the same profile; an incomplete set is
    skipped in favour of the next complete result;
  - never a run that measured an unreleased candidate (adapter `pre_release`).
Writes overview-dark.png, overview-light.png and latest.json (which runs were used). Display names can be set in
<output>/labels.json ({"product-id": "Name"}).
"""
import argparse
import glob
import json
import os
import subprocess
import tempfile

from . import overview

FAMILIES = ['functional', 'failure', 'redis', 'detection', 'performance', 'providers']
FOLDERS = {'functional': 'platform', 'failure': 'failure', 'redis': 'redis', 'detection': 'detection',
           'performance': 'performance', 'providers': 'providers'}


def gh(*args):
    return subprocess.run(['gh', *args], check=True, capture_output=True, text=True).stdout


def runs(repo, limit):
    data = json.loads(gh('api', f'repos/{repo}/actions/workflows/bench.yml/runs?status=success&per_page={limit}'))
    return [r for r in data.get('workflow_runs', []) if r.get('event') in ('workflow_dispatch', 'schedule')]


def download(repo, run_id, base):
    target = os.path.join(base, str(run_id))
    if not os.path.isdir(target):
        try:
            gh('run', 'download', str(run_id), '-R', repo, '-n', 'results-public', '-D', target)
        except subprocess.CalledProcessError:
            os.makedirs(target, exist_ok=True)  # expired or missing artifact: an empty folder, skipped below
    return target


def families_in(folder):
    manifest = os.path.join(folder, 'manifest.json')
    products = json.load(open(manifest)).get('products', []) if os.path.exists(manifest) else []
    if any(pre_release(p) for p in products):
        return {}  # the README shows released versions only; a candidate's runs stay in their own overview
    found = {}
    for family in FAMILIES:
        files = glob.glob(os.path.join(folder, FOLDERS[family], '*.json'))
        if not files:
            continue
        if family == 'performance':
            if not any(json.load(open(f)).get('platform') == 'velocity' for f in files):
                continue
        if family != 'providers' and len(products) < 2:
            continue
        found[family] = files
    return found


def pre_release(product_id):
    path = os.path.join(overview.ROOT, 'products', f'{product_id}.json')
    return os.path.exists(path) and bool(json.load(open(path)).get('pre_release'))


def detection_chunk(files):
    """(profile, chunk) of a detection result, chunk None for a full pass."""
    for path in files:
        record = json.load(open(path))
        if 'rows' in record:
            return record.get('profile', 'enforce'), record.get('chunk')
    return None, None


def select(repo, base, limit=60):
    chosen, used = {}, {}
    pending = {}  # profile -> {chunk: folder}
    for run in runs(repo, limit):
        if len(chosen) == len(FAMILIES):
            break
        folder = download(repo, run['id'], base)
        for family, files in families_in(folder).items():
            if family in chosen:
                continue
            if family == 'detection':
                profile, chunk = detection_chunk(files)
                if chunk:
                    k, n = chunk.split('/')
                    pending.setdefault((profile, n), {}).setdefault(k, folder)
                    if len(pending[(profile, n)]) == int(n):
                        chosen[family] = sorted(set(pending[(profile, n)].values()))
                    continue
            chosen[family] = [folder]
        for family, folders in chosen.items():
            used.setdefault(family, [os.path.basename(f) for f in folders])
    return chosen, used


def main():
    parser = argparse.ArgumentParser(prog='bench.latest')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--limit', type=int, default=60)
    args = parser.parse_args()
    labels_path = os.path.join(args.output, 'labels.json')
    labels = json.load(open(labels_path)) if os.path.exists(labels_path) else {}
    with tempfile.TemporaryDirectory() as base:
        chosen, used = select(args.repo, base, args.limit)
        if not chosen:
            raise SystemExit('no complete results found')
        os.makedirs(args.output, exist_ok=True)
        with tempfile.TemporaryDirectory() as out:
            for theme in ('dark', 'light'):
                html_path, png = overview.write(chosen, os.path.join(out, theme), labels, theme)
                if not png:
                    raise SystemExit('overview.png not rendered: no Chrome or Chromium found (set BENCH_CHROME)')
                os.replace(png, os.path.join(args.output, f'overview-{theme}.png'))
    with open(os.path.join(args.output, 'latest.json'), 'w') as handle:
        json.dump(dict(runs=used), handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps(used))


if __name__ == '__main__':
    main()
