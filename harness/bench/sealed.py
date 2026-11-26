"""Sealed detection dataset: drawn with a secret seed right before a run, published only after it.

The day's and week's datasets are public before the runs that use them, so any service can add those exact addresses
and reach 100 %. A sealed version uses the same sources, cohorts and rules (bench.dataset), but its seed is random and
kept back, and nothing but its SHA-256 is published until the runs are done:

  python3 -m bench.dataset seal                        # builds detection-v2/sealed-<stamp>/, prints version and hash
  BENCH_DATASET=sealed-<stamp> python3 -m bench run detection ...
  BENCH_DATASET=sealed-<stamp> python3 -m bench run providers ...
  python3 -m bench.dataset reveal sealed-<stamp>       # writes dataset.public.jsonl and the seed

Anyone can then check that the revealed file matches the hash posted before the run. The candidate pools (provider
server lists, Tor exits, proxy lists, the RIPE Atlas archive) stay public as before; only the draw is secret, so
nobody can know which few hundred of them will be asked.
"""
import datetime
import hashlib
import json
import os
import random
import secrets

from . import dataset as d


def _paths(version):
    out = os.path.join(d.V2, version)
    return out, os.path.join(out, 'manifest.json'), os.path.join(d.PRIVATE_DIR, f'{version}.seed')


def seal():
    now = datetime.datetime.now(datetime.timezone.utc)
    version = 'sealed-' + now.strftime('%Y%m%dT%H%M%SZ')
    out, manifest_path, seed_path = _paths(version)
    src = d.Sources(out)
    seed = secrets.randbits(63)
    rng = random.Random(seed)
    vpn, vpn_all, vpn_stats = d.sample_vpn(src, rng, now)
    tor, tor_set = d.sample_tor(src, rng)
    lists, stale_lists = d.live_lists(now)
    proxies, _, proxy_candidates = d.sample_proxies(src, rng, tor_set | vpn_all, lists)
    archive = (now.date() - datetime.timedelta(days=1)).isoformat()
    from .access import AccessNetworks
    ripe, conflicts, ripe_stats = d.sample_ripe(src, rng, archive, tor_set | vpn_all, AccessNetworks.from_sources(src))
    items, dropped = d.dedupe(vpn + tor + [p for p in proxies if p['ip'] not in vpn_all] + ripe)
    for entry in items:
        entry['id'] = d.stable_id(entry)
    items.sort(key=lambda i: i['id'])
    private = d.private_path(version)
    d.write_jsonl(private, items, public=False)
    os.makedirs(d.PRIVATE_DIR, exist_ok=True)
    with open(seed_path, 'w') as handle:
        handle.write(f'{seed}\n')
    digest = hashlib.sha256(open(private, 'rb').read()).hexdigest()
    manifest = dict(schema=2, name=f'mc-antivpn-bench detection v2 {version}', version=version, sealed=True,
                    built_at=now.isoformat(timespec='seconds'), ripe_archive_date=archive, counts=d.counts_of(items),
                    total=len(items), sha256_private=digest,
                    stats=dict(vpn_stats, proxy_candidates=proxy_candidates, proxy_lists=sorted(lists),
                               proxy_lists_left_out=stale_lists, residential_conflicts=conflicts,
                               duplicates_dropped=dropped, candidates=dict(vpn_stats['candidates'], **ripe_stats)))
    os.makedirs(out, exist_ok=True)
    with open(manifest_path, 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps(dict(version=version, sha256_private=digest, counts=manifest['counts'], total=len(items)), indent=2))
    return version


def reveal(version):
    out, manifest_path, seed_path = _paths(version)
    manifest = json.load(open(manifest_path))
    private = d.private_path(version)
    if hashlib.sha256(open(private, 'rb').read()).hexdigest() != manifest['sha256_private']:
        raise SystemExit(f'{version}: the private file no longer matches the sealed hash')
    items = [json.loads(line) for line in open(private)]
    d.write_jsonl(os.path.join(out, 'dataset.public.jsonl'), items)
    manifest.update(sealed=False, seed=int(open(seed_path).read()),
                    revealed_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'))
    with open(manifest_path, 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(f'{version}: revealed {len(items)} items, sha256 {manifest["sha256_private"]}')
