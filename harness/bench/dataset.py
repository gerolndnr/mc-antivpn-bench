"""Labelled detection dataset with explicit provenance.

Ground truth comes from the party that operates the address, never from a
detection provider:

  commercial_vpn  VPN operators' own published server lists
  fresh_vpn       operator-listed today, absent from the same operator's list in the
                  newest Internet Archive capture at least MIN_FRESH_DAYS old
                  (NordVPN: operator-published created_at within FRESH_DAYS)
  tor             Tor Project bulk exit list
  proxy           open proxies listed as working by >= 2 independently maintained,
                  checked public lists on the same day (weaker: community-listed)
  residential     RIPE Atlas probes hosted at home (volunteer-tagged), public egress
  mobile_cgnat    RIPE Atlas probes on LTE/4G/5G/Starlink, public (CGNAT) egress
  *_v6            the same sources' IPv6 addresses

Every item records source URL, fetch time and the SHA-256 of the raw snapshot.
Residential and mobile addresses belong to volunteers: the public dataset carries
only the probe id and snapshot date (rebuildable from the RIPE Atlas archive),
never the address.

Deterministic: the same snapshots and seed always yield the same sample.
"""
import datetime
import gzip
import hashlib
import ipaddress
import json
import os
import random
import socket
import sys
import urllib.request

from .artifacts import ROOT, USER_AGENT

OUT = os.path.join(ROOT, 'datasets', 'detection-v1')
CACHE = os.path.join(ROOT, 'cache', 'sources')
SEED = 20261005
MIN_FRESH_DAYS = 14
FRESH_DAYS = 30
PER_PROVIDER = 25
TARGETS = dict(commercial_vpn=125, fresh_vpn=60, tor=80, proxy=100, residential=150, mobile_cgnat=100,
               residential_v6=60, vpn_v6=40)
HOME_TAGS = {'home', 'dsl', 'cable', 'fibre', 'ftth', 'adsl', 'vdsl', 'docsis', 'gpon'}
MOBILE_TAGS = {'lte', '4g', '5g', 'mobile', 'starlink', 'cgnat', '3g'}
EXCLUDE_TAGS = {'datacentre', 'datacenter', 'data-center', 'core', 'vps', 'cloud', 'hosting', 'colo', 'ixp',
                'anchor', 'vpn', 'tor', 'academic', 'office', 'business'}


def fetch_with_retries(url, attempts=5):
    """Large archive responses occasionally break mid-transfer; retry with backoff."""
    import http.client
    import time
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(request, timeout=300) as response:
                return response.read()
        except (OSError, http.client.HTTPException, ValueError) as error:
            if attempt == attempts - 1:
                raise
            print(f'fetch failed ({type(error).__name__}), retrying: {url}', file=sys.stderr)
            time.sleep(5 * (attempt + 1))


class Sources:
    """Fetches raw snapshots once, keeps them in the git-ignored cache, records provenance."""

    def __init__(self):
        os.makedirs(CACHE, exist_ok=True)
        self.records = {}

    def get(self, name, url, public=True):
        # Public snapshots are committed (datasets/detection-v1/sources); everything else is cached.
        committed = os.path.join(OUT, 'sources', name + '.gz')
        path = committed if os.path.exists(committed) else os.path.join(CACHE, name + '.gz')
        meta_path = path + '.json'
        if os.path.exists(path) and os.path.exists(meta_path):
            with gzip.open(path, 'rb') as handle:
                data = handle.read()
            with open(meta_path) as handle:
                meta = json.load(handle)
        else:
            data = fetch_with_retries(url)
            if data[:2] == b'\x1f\x8b':  # archive captures keep the original content encoding
                data = gzip.decompress(data)
            meta = dict(url=url, fetched_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                        sha256=hashlib.sha256(data).hexdigest(), bytes=len(data), public=public)
            with gzip.open(path, 'wb') as handle:
                handle.write(data)
            with open(meta_path, 'w') as handle:
                json.dump(meta, handle)
        self.records[name] = meta
        return data

    def resolved(self, name, hostnames):
        """DNS A records, resolved once and frozen like any other snapshot."""
        committed = os.path.join(OUT, 'sources', name + '.json')
        path = committed if os.path.exists(committed) else os.path.join(CACHE, name + '.json')
        if not os.path.exists(path):
            out = {}
            for hostname in hostnames:
                try:
                    out[hostname] = sorted({info[4][0] for info in socket.getaddrinfo(hostname, 443, socket.AF_INET)})
                except OSError:
                    out[hostname] = []
            with open(path, 'w') as handle:
                json.dump(dict(resolved_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                               records=out), handle, sort_keys=True)
        data = open(path, 'rb').read()
        payload = json.loads(data)
        self.records[name] = dict(source='DNS A records', fetched_at=payload['resolved_at'],
                                  sha256=hashlib.sha256(data).hexdigest(), public=True)
        return payload['records']

    def json(self, name, url, public=True):
        data = self.get(name, url, public)
        text = data.decode('utf-8')
        if name == 'pia' or name.startswith('pia-'):
            text = text.split('\n', 1)[0]  # the file carries a detached signature after the JSON line
        return json.loads(text)

    def wayback(self, name, url, older_than_days):
        """Newest Internet Archive capture at least `older_than_days` old."""
        cutoff = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=older_than_days))
        index = json.loads(self.get(f'{name}-cdx', 'https://web.archive.org/cdx/search/cdx?url=' + url +
                                    '&output=json&fl=timestamp,statuscode&filter=statuscode:200&from=2025'))
        captures = [row[0] for row in index[1:] if row[0] <= cutoff.strftime('%Y%m%d%H%M%S')]
        if not captures:
            return None, None
        stamp = captures[-1]
        return stamp, self.get(f'{name}-wayback-{stamp}', f'https://web.archive.org/web/{stamp}id_/https://{url}')


def slash24(ip):
    address = ipaddress.ip_address(ip)
    return str(ipaddress.ip_network(f'{ip}/{24 if address.version == 4 else 48}', strict=False))


def public_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def spread(candidates, count, rng, key=lambda c: c['country'], per_bucket=None, bucket=None):
    """Round-robin over `key` groups (e.g. countries) after a seeded shuffle, max per bucket."""
    candidates = sorted(candidates, key=lambda c: c['ip'])
    rng.shuffle(candidates)
    groups = {}
    for candidate in candidates:
        groups.setdefault(key(candidate) or '?', []).append(candidate)
    order = sorted(groups)
    rng.shuffle(order)
    used, buckets, picked = set(), {}, []
    while len(picked) < count and any(groups[g] for g in order):
        for group in order:
            while groups[group]:
                candidate = groups[group].pop()
                net = slash24(candidate['ip'])
                b = bucket(candidate) if bucket else None
                if net in used or (per_bucket and b is not None and buckets.get(b, 0) >= per_bucket):
                    continue
                used.add(net)
                if b is not None:
                    buckets[b] = buckets.get(b, 0) + 1
                picked.append(candidate)
                break
            if len(picked) >= count:
                break
    return picked


# ------------------------------------------------------------------ VPN
def vpn_candidates(src):
    """Current operator lists -> {provider: [candidate]} for IPv4 and IPv6."""
    v4, v6 = {}, {}
    mullvad = src.json('mullvad', 'https://api.mullvad.net/www/relays/all/')
    for relay in mullvad:
        if relay.get('active') and relay.get('type') == 'wireguard':
            base = dict(provider='mullvad', country=relay['country_code'].upper(), evidence=dict(
                hostname=relay['hostname'], owned=relay.get('owned'), hoster=relay.get('provider')))
            if public_ip(relay.get('ipv4_addr_in', '')):
                v4.setdefault('mullvad', []).append(dict(base, ip=relay['ipv4_addr_in']))
            if public_ip(relay.get('ipv6_addr_in', '')):
                v6.setdefault('mullvad', []).append(dict(base, ip=relay['ipv6_addr_in']))
    nord = src.json('nordvpn', 'https://api.nordvpn.com/v1/servers?limit=20000&fields%5Bservers.station%5D'
                               '&fields%5Bservers.created_at%5D&fields%5Bservers.status%5D'
                               '&fields%5Bservers.hostname%5D&fields%5Bservers.ipv6_station%5D')
    for server in nord:
        if server.get('status') == 'online' and public_ip(server.get('station', '')):
            v4.setdefault('nordvpn', []).append(dict(
                ip=server['station'], provider='nordvpn', country=server['hostname'][:2].upper(),
                evidence=dict(hostname=server['hostname'], created_at=server['created_at'])))
    pia = src.json('pia', 'https://serverlist.piaservers.net/vpninfo/servers/v6')
    for region in pia['regions']:
        for server in region['servers'].get('wg', []):
            if public_ip(server['ip']):
                v4.setdefault('pia', []).append(dict(ip=server['ip'], provider='pia', country=region['country'],
                                                     evidence=dict(cn=server['cn'], region=region['name'])))
    ivpn = src.json('ivpn', 'https://api.ivpn.net/v5/servers.json')
    for gateway in ivpn['wireguard']:
        for host in gateway['hosts']:
            if public_ip(host.get('host', '')):
                v4.setdefault('ivpn', []).append(dict(ip=host['host'], provider='ivpn', country=gateway['country_code'],
                                                      evidence=dict(hostname=host['hostname'], isp=host.get('isp'))))
    surfshark = src.json('surfshark', 'https://api.surfshark.com/v4/server/clusters')
    resolved = src.resolved('surfshark-dns', sorted({c['connectionName'] for c in surfshark if c.get('connectionName')}))
    for cluster in surfshark:
        name = cluster.get('connectionName')
        for ip in resolved.get(name, []):
            if public_ip(ip):
                v4.setdefault('surfshark', []).append(dict(ip=ip, provider='surfshark', country=cluster['countryCode'],
                                                           evidence=dict(hostname=name, resolved=True)))
    src.records['surfshark']['note'] = 'cluster host names resolved via DNS at fetch time'
    return v4, v6


def previous_ips(src, provider):
    """IPv4 addresses in the operator's newest archived list >= MIN_FRESH_DAYS old."""
    urls = dict(mullvad='api.mullvad.net/www/relays/all/', pia='serverlist.piaservers.net/vpninfo/servers/v6',
                ivpn='api.ivpn.net/v5/servers.json')
    stamp, data = src.wayback(provider, urls[provider], MIN_FRESH_DAYS)
    if not data:
        return None, None
    text = data.decode('utf-8', 'replace')
    if provider == 'pia':
        text = text.split('\n', 1)[0]
    payload = json.loads(text)
    ips = set()
    if provider == 'mullvad':
        ips = {r.get('ipv4_addr_in') for r in payload}
    elif provider == 'pia':
        for region in payload['regions']:
            for group in region['servers'].values():
                ips |= {s['ip'] for s in group}
    elif provider == 'ivpn':
        for kind in ('wireguard', 'openvpn'):
            for gateway in payload.get(kind, []):
                ips |= {h.get('host') for h in gateway.get('hosts', [])}
    return stamp, {ip for ip in ips if ip}


# ------------------------------------------------------------------ RIPE Atlas
RIPE_ARCHIVE_DATE = '2026-10-04'


def ripe_archive_url(date):
    return f'https://atlas.ripe.net/api/v2/probes/archive/?date={date}&format=json'


def ripe_probes(src, date=RIPE_ARCHIVE_DATE):
    """Connected public probes from the RIPE Atlas daily archive (exactly reproducible)."""
    payload = json.loads(src.get(f'ripe-archive-{date}', ripe_archive_url(date), public=False))
    return [p for p in payload['results'] if p.get('is_public') and (p.get('status') or {}).get('name') == 'Connected']


def probe_tags(probe):
    return {t['slug'] if isinstance(t, dict) else t for t in probe.get('tags', [])}


# ------------------------------------------------------------------ build
def build():
    rng = random.Random(SEED)
    src = Sources()
    now = datetime.datetime.now(datetime.timezone.utc)
    items = []

    def add(cohort, label, candidate, source, extra=None):
        items.append(dict(cohort=cohort, label=label, ip=candidate['ip'],
                          family=ipaddress.ip_address(candidate['ip']).version, source=source,
                          provider=candidate.get('provider'), country=candidate.get('country'),
                          evidence=dict(candidate.get('evidence', {}), **(extra or {}))))

    # --- VPN, current lists
    v4, v6 = vpn_candidates(src)
    fresh = []
    fresh_meta = {}
    for provider in ('mullvad', 'pia', 'ivpn'):
        stamp, before = previous_ips(src, provider)
        if before is None:
            continue
        fresh_meta[provider] = dict(baseline_capture=stamp)
        prior_nets = {slash24(ip) for ip in before if public_ip(ip) and ipaddress.ip_address(ip).version == 4}
        for candidate in v4.get(provider, []):
            if candidate['ip'] not in before:
                fresh.append(dict(candidate, evidence=dict(candidate['evidence'], absent_from_capture=stamp,
                                                           new_slash24=slash24(candidate['ip']) not in prior_nets)))
    for candidate in v4.get('nordvpn', []):
        created = datetime.datetime.fromisoformat(candidate['evidence']['created_at']).replace(
            tzinfo=datetime.timezone.utc)
        if (now - created).days <= FRESH_DAYS:
            fresh.append(dict(candidate, evidence=dict(candidate['evidence'], fresh_rule=f'created_at<={FRESH_DAYS}d')))
    fresh_meta['nordvpn'] = dict(rule=f'operator created_at within {FRESH_DAYS} days')
    fresh_picked = spread(fresh, TARGETS['fresh_vpn'], rng, key=lambda c: c['provider'], per_bucket=20,
                          bucket=lambda c: c['provider'])
    fresh_ips = {c['ip'] for c in fresh_picked}
    for candidate in fresh_picked:
        add('fresh_vpn', 'vpn', candidate, candidate['provider'])
    for provider in sorted(v4):
        pool = [c for c in v4[provider] if c['ip'] not in fresh_ips]
        if provider == 'nordvpn':
            pool = [c for c in pool if (now - datetime.datetime.fromisoformat(c['evidence']['created_at']).replace(
                tzinfo=datetime.timezone.utc)).days > 90]
        for candidate in spread(pool, PER_PROVIDER, rng):
            add('commercial_vpn', 'vpn', candidate, provider)
    pool = [c for provider in sorted(v6) for c in v6[provider]]
    for candidate in spread(pool, TARGETS['vpn_v6'], rng):
        add('vpn_v6', 'vpn', candidate, candidate['provider'])

    # --- Tor
    tor = src.get('tor-bulk', 'https://check.torproject.org/torbulkexitlist').decode().split()
    tor_candidates = [dict(ip=ip, provider='tor', country=None) for ip in tor if public_ip(ip)]
    for candidate in spread(tor_candidates, TARGETS['tor'], rng, key=lambda c: slash24(c['ip'])[:3]):
        add('tor', 'tor', candidate, 'torproject-bulk-exit-list')
    tor_set = set(tor)

    # --- Proxies: >= 2 independent, checked lists
    lists = dict(
        monosans='https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
        proxifly='https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt',
        vakhov='https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist.txt')
    seen = {}
    for name, url in lists.items():
        for line in src.get(f'proxy-{name}', url).decode('utf-8', 'replace').split():
            host = line.split('://')[-1].rsplit(':', 1)[0].strip('[]')
            if public_ip(host):
                seen.setdefault(host, set()).add(name)
    vpn_all = {c['ip'] for provider in v4 for c in v4[provider]} | {c['ip'] for p in v6 for c in v6[p]}
    proxy_candidates = [dict(ip=ip, provider='open-proxy', country=None, evidence=dict(listed_by=sorted(names)))
                        for ip, names in seen.items() if len(names) >= 2 and ip not in tor_set and ip not in vpn_all
                        and ipaddress.ip_address(ip).version == 4]
    for candidate in spread(proxy_candidates, TARGETS['proxy'], rng, key=lambda c: slash24(c['ip'])[:3]):
        add('proxy', 'proxy', candidate, 'checked-public-proxy-lists')
    proxy_set = set(seen)

    # --- RIPE Atlas residential / mobile (never published with addresses)
    probes = ripe_probes(src)
    infrastructure = tor_set | proxy_set | vpn_all
    conflicts = 0
    residential, mobile, residential6 = [], [], []
    for probe in probes:
        tags = probe_tags(probe)
        if tags & EXCLUDE_TAGS:
            continue
        evidence = dict(probe_id=probe['id'], archive_date=RIPE_ARCHIVE_DATE,
                        tags=sorted(tags & (HOME_TAGS | MOBILE_TAGS)))
        v4ip, v6ip = probe.get('address_v4'), probe.get('address_v6')
        if v4ip in infrastructure or v6ip in infrastructure:
            conflicts += 1
            continue
        is_mobile = bool(tags & MOBILE_TAGS)
        is_home = bool(tags & HOME_TAGS)
        if v4ip and public_ip(v4ip) and 'system-ipv4-works' in tags:
            candidate = dict(ip=v4ip, provider=f'AS{probe.get("asn_v4")}', country=probe.get('country_code'),
                             evidence=dict(evidence, asn=probe.get('asn_v4')))
            if is_mobile:
                mobile.append(candidate)
            elif is_home:
                residential.append(candidate)
        if v6ip and public_ip(v6ip) and is_home and not is_mobile and 'system-ipv6-works' in tags:
            residential6.append(dict(ip=v6ip, provider=f'AS{probe.get("asn_v6")}', country=probe.get('country_code'),
                                     evidence=dict(evidence, asn=probe.get('asn_v6'))))
    for cohort, pool, per_asn in (('residential', residential, 2), ('mobile_cgnat', mobile, 3),
                                  ('residential_v6', residential6, 2)):
        for candidate in spread(pool, TARGETS[cohort], rng, per_bucket=per_asn, bucket=lambda c: c['provider']):
            add(cohort, 'non_vpn', candidate, 'ripe-atlas')

    # --- de-duplicate across cohorts (keep first)
    unique, dropped = [], 0
    seen_ips = set()
    for item in items:
        if item['ip'] in seen_ips:
            dropped += 1
            continue
        seen_ips.add(item['ip'])
        unique.append(item)
    for index, item in enumerate(sorted(unique, key=lambda i: (i['cohort'], i['ip']))):
        item['id'] = f'{item["cohort"]}-{index:04d}'
    unique.sort(key=lambda i: i['id'])
    write_outputs(unique, src, dict(fresh=fresh_meta, residential_conflicts=conflicts, duplicates_dropped=dropped,
                                    candidates=dict(commercial_vpn={p: len(v) for p, v in v4.items()},
                                                    fresh=len(fresh), proxy=len(proxy_candidates),
                                                    residential=len(residential), mobile=len(mobile),
                                                    residential_v6=len(residential6))))


def write_outputs(items, src, stats):
    os.makedirs(OUT, exist_ok=True)
    private_dir = os.path.join(ROOT, 'cache', 'private')
    os.makedirs(private_dir, exist_ok=True)
    with open(os.path.join(private_dir, 'detection-v1.private.jsonl'), 'w') as handle:
        for item in items:
            handle.write(json.dumps(item, sort_keys=True) + '\n')
    with open(os.path.join(OUT, 'dataset.public.jsonl'), 'w') as handle:
        for item in items:
            public = dict(item)
            if item['source'] == 'ripe-atlas':
                public.pop('ip')
                public['rebuild'] = dict(archive=ripe_archive_url(item['evidence']['archive_date']),
                                         probe_id=item['evidence']['probe_id'], field=f'address_v{item["family"]}')
            handle.write(json.dumps(public, sort_keys=True) + '\n')
    counts = {}
    for item in items:
        counts[item['cohort']] = counts.get(item['cohort'], 0) + 1
    manifest = dict(schema=1, name='mc-antivpn-bench detection v1', seed=SEED,
                    built_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                    counts=counts, total=len(items), stats=stats,
                    sources={k: {f: v for f, v in m.items()} for k, m in sorted(src.records.items())
                             },
                    sha256_private=hashlib.sha256(open(os.path.join(private_dir, 'detection-v1.private.jsonl'),
                                                       'rb').read()).hexdigest())
    with open(os.path.join(OUT, 'manifest.json'), 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write('\n')
    print(json.dumps(dict(counts=counts, total=len(items), stats=stats), indent=2))


def materialize():
    """Rebuild the private dataset (with addresses) from the public one + RIPE Atlas archive."""
    src = Sources()
    archives = {}
    private = []
    for line in open(os.path.join(OUT, 'dataset.public.jsonl')):
        item = json.loads(line)
        rebuild = item.pop('rebuild', None)
        if rebuild:
            date = item['evidence']['archive_date']
            if date not in archives:
                payload = json.loads(src.get(f'ripe-archive-{date}', rebuild['archive'], public=False))
                archives[date] = {p['id']: p for p in payload['results']}
            probe = archives[date][rebuild['probe_id']]
            item['ip'] = probe[rebuild['field']]
        private.append(item)
    private_dir = os.path.join(ROOT, 'cache', 'private')
    os.makedirs(private_dir, exist_ok=True)
    path = os.path.join(private_dir, 'detection-v1.private.jsonl')
    with open(path, 'w') as handle:
        for item in private:
            handle.write(json.dumps(item, sort_keys=True) + '\n')
    expected = json.load(open(os.path.join(OUT, 'manifest.json')))['sha256_private']
    actual = hashlib.sha256(open(path, 'rb').read()).hexdigest()
    print(json.dumps(dict(items=len(private), sha256=actual, matches_manifest=actual == expected)))
    if actual != expected:
        sys.exit('materialized dataset does not match the published manifest hash')


if __name__ == '__main__':
    if sys.argv[1:] == ['build']:
        build()
    elif sys.argv[1:] == ['materialize']:
        materialize()
