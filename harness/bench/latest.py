"""The overview for the README: the newest complete result of every product in every family, from this repository's
workflow runs.

  GH_TOKEN=... python3 -m bench.latest --repo gerolndnr/mc-antivpn-bench --output docs/overview

Reads, newest first, successful `benchmark` runs started by hand or by the schedule, and takes per family and per
product the newest result of that product. A run that measured only some products (a product added later) therefore
adds those products and leaves the others' results in place.
  - Detection: a nightly chunk counts only together with the other chunks of the same series; a run limited to part
    of the dataset never counts. The graphic shows the keyed profile (proxycheck_key) only once every product with a
    detection result has it, and the keyless one (enforce) until then, so one table never mixes profiles.
  - Performance on Velocity only.
  - Providers: the newest run.
  - Never a run that measured an unreleased candidate (adapter `pre_release`).
Writes overview-dark.png, overview-light.png and latest.json (which runs each product came from). Display names can
be set in <output>/labels.json ({"product-id": "Name"}).
"""
import argparse
import glob
import json
import os
import shutil
import subprocess
import tempfile

from . import overview

FAMILIES = ['functional', 'failure', 'redis', 'detection', 'performance', 'providers']
# Result folders per family; the first one decides whether a run has a result for a product.
FOLDERS = {'functional': ['platform', 'clean-install', 'upgrade', 'invalid-reload', 'secrets'], 'failure': ['failure'],
           'redis': ['redis'], 'detection': ['detection'], 'performance': ['performance'], 'providers': ['providers']}
HEADLINE = ['proxycheck_key', 'enforce']
DATASET = os.path.join(overview.ROOT, 'datasets', 'detection-v1', 'dataset.public.jsonl')


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


def pre_release(product_id):
    path = os.path.join(overview.ROOT, 'products', f'{product_id}.json')
    return os.path.exists(path) and bool(json.load(open(path)).get('pre_release'))


def load(path):
    try:
        with open(path) as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def dataset_size():
    with open(DATASET) as handle:
        return sum(1 for line in handle if line.strip())


def product_files(folder, family):
    """{product: [paths]} of one run and family (performance: Velocity only)."""
    out = {}
    for sub in FOLDERS[family]:
        for path in sorted(glob.glob(os.path.join(folder, sub, '*.json'))):
            record = load(path)
            if not isinstance(record, dict) or 'product' not in record:
                continue
            if family == 'performance' and record.get('platform', 'velocity') != 'velocity':
                continue
            out.setdefault(record['product'], []).append(path)
    if family == 'functional':
        # A product counts as measured here only with a platform result.
        out = {p: files for p, files in out.items() if any(os.sep + 'platform' + os.sep in f for f in files)}
    return out


def detection_passes(folder, total):
    """[(profile, chunk or None, path, products)] of one run; passes over part of the dataset are left out."""
    out = []
    for path in sorted(glob.glob(os.path.join(folder, 'detection', '*.json'))):
        record = load(path)
        if not isinstance(record, dict) or 'rows' not in record:
            continue
        chunk = record.get('chunk')
        subjects = {r['subject'] for r in record['rows']}
        if not chunk and len(subjects) < total:
            continue
        products = sorted({p for r in record['rows'] for p in r.get('products', {})})
        out.append((record.get('profile', 'enforce'), chunk, path, products))
    return out


def select(repo, base, limit=60):
    """{family: {product: [(run_id, folder, paths)]}} and the providers folder."""
    total = dataset_size()
    chosen = {family: {} for family in FAMILIES if family not in ('providers', 'detection')}
    detection = {}  # product -> profile -> [(run_id, folder, [paths])]
    pending = {}  # (product, profile, n) -> {k: (run_id, folder, path)}
    providers = None
    for run in runs(repo, limit):
        folder = download(repo, run['id'], base)
        manifest = load(os.path.join(folder, 'manifest.json')) or {}
        if any(pre_release(p) for p in manifest.get('products', [])):
            continue  # the README shows released versions only; a candidate's runs stay in their own overview
        run_id = str(run['id'])
        if providers is None and glob.glob(os.path.join(folder, 'providers', '*.json')):
            providers = (run_id, folder)
        for family in chosen:
            for product, files in product_files(folder, family).items():
                chosen[family].setdefault(product, [(run_id, folder, files)])
        for profile, chunk, path, products in detection_passes(folder, total):
            for product in products:
                done = detection.setdefault(product, {})
                if profile in done:
                    continue
                if not chunk:
                    done[profile] = [(run_id, folder, [path])]
                    continue
                k, n = chunk.split('/')
                series = pending.setdefault((product, profile, n), {})
                series.setdefault(k, (run_id, folder, path))
                if len(series) == int(n):
                    done[profile] = [(r, f, [p]) for _, (r, f, p) in sorted(series.items())]
    measured = [p for p, profiles in detection.items() if any(x in profiles for x in HEADLINE)]
    profile = next((x for x in HEADLINE if measured and all(x in detection[p] for p in measured)), 'enforce')
    chosen['detection'] = {p: profiles[profile] for p, profiles in detection.items() if profile in profiles}
    return chosen, providers, profile


def merge(chosen, providers, profile, base):
    """One folder per family and source run, holding only the products taken from that run (and its manifest), so
    overview.build counts every product once."""
    dirs = {}
    for family, by_product in chosen.items():
        by_run = {}
        for product, sources in by_product.items():
            for run_id, folder, files in sources:
                by_run.setdefault((run_id, folder), {})[product] = files
        for (run_id, folder), products in sorted(by_run.items()):
            target = os.path.join(base, 'merged', family, run_id)
            os.makedirs(target, exist_ok=True)
            if os.path.exists(os.path.join(folder, 'manifest.json')):
                shutil.copy(os.path.join(folder, 'manifest.json'), target)
            for product, files in products.items():
                for path in files:
                    sub = os.path.join(target, os.path.basename(os.path.dirname(path)))
                    os.makedirs(sub, exist_ok=True)
                    if family == 'detection':
                        # A pass holds every product of its run: keep the rows of the products taken from it.
                        record = load(path)
                        keep = set(products)
                        out = os.path.join(sub, os.path.basename(path))
                        if os.path.exists(out):
                            continue
                        record['rows'] = [dict(r, products={p: v for p, v in r['products'].items() if p in keep})
                                          for r in record['rows']]
                        with open(out, 'w') as handle:
                            json.dump(record, handle)
                    else:
                        shutil.copy(path, sub)
            dirs.setdefault(family, []).append(target)
    if providers:
        dirs['providers'] = [providers[1]]
    return dirs


def sources(chosen, providers):
    out = {family: {p: sorted({s[0] for s in srcs}) for p, srcs in sorted(by.items())} for family, by in chosen.items()}
    if providers:
        out['providers'] = {'services': [providers[0]]}
    return out


def main():
    parser = argparse.ArgumentParser(prog='bench.latest')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--limit', type=int, default=60)
    args = parser.parse_args()
    labels_path = os.path.join(args.output, 'labels.json')
    labels = json.load(open(labels_path)) if os.path.exists(labels_path) else {}
    with tempfile.TemporaryDirectory() as base:
        chosen, providers, profile = select(args.repo, base, args.limit)
        if not any(chosen.values()) and not providers:
            raise SystemExit('no complete results found')
        dirs = merge(chosen, providers, profile, base)
        used = sources(chosen, providers)
        os.makedirs(args.output, exist_ok=True)
        with tempfile.TemporaryDirectory() as out:
            for theme in ('dark', 'light'):
                html_path, png = overview.write(dirs, os.path.join(out, theme), labels, theme)
                if not png:
                    raise SystemExit('overview.png not rendered: no Chrome or Chromium found (set BENCH_CHROME)')
                os.replace(png, os.path.join(args.output, f'overview-{theme}.png'))
    runs_used = {family: sorted({r for rs in by.values() for r in rs}) for family, by in used.items()}
    with open(os.path.join(args.output, 'latest.json'), 'w') as handle:
        json.dump(dict(runs=runs_used, products=used, detection_profile=profile), handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps(dict(runs=runs_used, detection_profile=profile)))


if __name__ == '__main__':
    main()
