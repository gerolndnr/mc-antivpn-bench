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
  - Providers: per service the newest run in which it answered; a service that was down keeps its earlier result.
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

from . import dataset, overview, score

FAMILIES = ['functional', 'failure', 'redis', 'detection', 'performance', 'providers']
# Result folders per family; the first one decides whether a run has a result for a product.
FOLDERS = {'functional': ['platform', 'clean-install', 'upgrade', 'invalid-reload', 'secrets'], 'failure': ['failure'],
           'redis': ['redis'], 'detection': ['detection'], 'performance': ['performance'], 'providers': ['providers']}
HEADLINE = ['proxycheck_key', 'enforce']


def gh(*args):
    return subprocess.run(['gh', *args], check=True, capture_output=True, text=True).stdout


def runs(repo, limit):
    """The newest `limit` successful manual and nightly runs, newest first. Paged: pushes also start the workflow
    (contract tests only), and a busy day must not push a plugin's only result of a family out of reach."""
    out, page = [], 1
    while len(out) < limit:
        data = json.loads(gh('api', f'repos/{repo}/actions/workflows/bench.yml/runs?status=success&per_page=100&page={page}'))
        batch = data.get('workflow_runs', [])
        out += [r for r in batch if r.get('event') in ('workflow_dispatch', 'schedule')]
        if len(batch) < 100:
            break
        page += 1
    return out[:limit]


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


def select(repo, base, limit=250):
    """{family: {product: [(run_id, folder, paths)]}} and the providers folder."""
    chosen = {family: {} for family in FAMILIES if family not in ('providers', 'detection')}
    detection = {}  # product -> (profile, core) -> [(run_id, folder, [paths])]
    pending = {}  # (product, profile, core, n) -> {k: (run_id, folder, path)}
    providers = None
    for run in runs(repo, limit):
        folder = download(repo, run['id'], base)
        manifest = load(os.path.join(folder, 'manifest.json')) or {}
        if any(pre_release(p) for p in manifest.get('products', [])):
            continue  # the README shows released versions only; a candidate's runs stay in their own overview
        run_id = str(run['id'])
        summary = load(os.path.join(folder, 'providers', 'summary.json'))
        if summary and summary.get('services'):
            providers = providers or dict(newest=(run_id, folder, summary), services={})
            for sid, entry in summary['services'].items():
                taken = providers['services'].get(sid)
                if taken is None or (score.unavailable(taken[2]) and not score.unavailable(entry)):
                    providers['services'][sid] = (run_id, folder, entry, summary.get('meta') or {})
        for family in chosen:
            for product, files in product_files(folder, family).items():
                chosen[family].setdefault(product, [(run_id, folder, files)])
        version = dataset.run_version(manifest)
        core = dataset.core_of(version)
        for profile, chunk, path, products in detection_passes(folder, len(dataset.public_items(version))):
            for product in products:
                done = detection.setdefault(product, {})
                if (profile, core) in done:
                    continue
                if not chunk:
                    done[(profile, core)] = [(run_id, folder, [path])]
                    continue
                k, n = chunk.split('/')
                series = pending.setdefault((product, profile, core, n), {})
                series.setdefault(k, (run_id, folder, path))
                if len(series) == int(n):
                    done[(profile, core)] = [(r, f, [p]) for _, (r, f, p) in sorted(series.items())]
    # The table compares the plugins it shows (newest version each; an older version is not drawn, so it must not hold
    # the others back) on one dataset core: the newest core every one of them has a complete pass on, keyed if all
    # have it there. A core every shown plugin lacks waits until all are measured on it.
    shown = set(overview.newest_only(list(detection)))
    measured = [p for p in detection if p in shown]
    cores = sorted({c for p in measured for _, c in detection[p]}, key=lambda c: (c != 'v1', c), reverse=True)
    pick = next(((x, c) for c in cores for x in HEADLINE if all((x, c) in detection[p] for p in measured)),
                ('enforce', 'v1'))
    chosen['detection'] = {p: detection[p][pick] for p in measured if pick in detection[p]}
    return chosen, providers, pick[0]


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
        # One summary: every service from its newest run in which it answered (a service that was down in, or not part
        # of, the newest run keeps its earlier result, labelled with that run's date; one only left out of it is labelled only from another day); the chains
        # and meta of the newest run.
        run_id, folder, newest = providers['newest']
        target = os.path.join(base, 'merged', 'providers', run_id)
        os.makedirs(os.path.join(target, 'providers'), exist_ok=True)
        if os.path.exists(os.path.join(folder, 'manifest.json')):
            shutil.copy(os.path.join(folder, 'manifest.json'), target)
        services, kept = {}, []
        dirs['providers'] = [target]
        for sid, (rid, src, entry, meta) in providers['services'].items():
            entry = dict(entry)
            if rid != run_id:
                # Down in the newest run: always tagged. Only left out of it (a run of a few services): tagged when
                # the earlier run is from another day.
                day = (meta.get('started') or '')[:10]
                if sid in (newest.get('services') or {}) or day != ((newest.get('meta') or {}).get('started') or '')[:10]:
                    entry['from_date'] = day
                extra = os.path.join(base, 'merged', 'providers', rid)
                if not os.path.exists(extra):
                    os.makedirs(extra)
                    if os.path.exists(os.path.join(src, 'manifest.json')):
                        shutil.copy(os.path.join(src, 'manifest.json'), extra)
                    dirs['providers'].append(extra)
            services[sid] = entry
            # The answers behind the entry, so the overview can recount it without stale addresses (bench.freshness).
            # Stable ids: services can come from runs on different dataset versions.
            source = os.path.join(src, 'providers', 'answers.jsonl')
            if os.path.exists(source):
                ids = dataset.stable_ids(dataset.run_version(load(os.path.join(src, 'manifest.json')) or {}))
                with open(source) as answers:
                    for line in answers:
                        row = json.loads(line)
                        if row.get('service') == sid:
                            kept.append(json.dumps(dict(row, id=ids.get(row['id'], row['id']))) + '\n')
        with open(os.path.join(target, 'providers', 'summary.json'), 'w') as handle:
            json.dump(dict(newest, services=services), handle)
        if kept:
            with open(os.path.join(target, 'providers', 'answers.jsonl'), 'w') as handle:
                handle.writelines(kept)
    return dirs


def sources(chosen, providers):
    out = {family: {p: sorted({s[0] for s in srcs}) for p, srcs in sorted(by.items())} for family, by in chosen.items()}
    if providers:
        out['providers'] = {sid: [rid] for sid, (rid, _, _, _) in sorted(providers['services'].items())}
    return out


def main():
    parser = argparse.ArgumentParser(prog='bench.latest')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--limit', type=int, default=250)
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
