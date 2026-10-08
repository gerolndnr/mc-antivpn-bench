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

Versions (METHODOLOGY 6):
  v1                     datasets/detection-v1, built once on 5 October 2026 (every run before v2)
  v2 core, weekly        datasets/detection-v2/core/<ISO week>: VPN servers, home and mobile probes
  v2 day, daily          datasets/detection-v2/<date>: that day's Tor exits and proxies + the week's core
  datasets/detection-v2/CURRENT names the newest day; a run records the version it used.
In v2 an address keeps its id across versions (stable_id), so runs on different days compare on the
addresses they share.
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
V2 = os.path.join(ROOT, 'datasets', 'detection-v2')
PRIVATE_DIR = os.path.join(ROOT, 'cache', 'private')
# A source list whose upstream file has not changed for this long no longer says what is listed today (vakhov's
# proxy list had not changed for eight months when v1 used it).
STALE_SOURCE_DAYS = 14
CACHE = os.path.join(ROOT, 'cache', 'sources')
SEED = 20261005
MIN_FRESH_DAYS = 14
FRESH_DAYS = 30
PER_PROVIDER = 25
TARGETS = dict(commercial_vpn=125, fresh_vpn=60, tor=80, proxy=100, residential=150, mobile_cgnat=100,
               residential_v6=60, vpn_v6=40)
HOME_TAGS = {'home', 'dsl', 'cable', 'fibre', 'ftth', 'adsl', 'vdsl', 'docsis', 'gpon'}
MOBILE_TAGS = {'lte', '4g', '5g', 'mobile', 'starlink', 'cgnat', '3g'}
# A volunteer's probe whose public address belongs to one of these networks does not reach the internet from a home
# connection, whatever its tags say. Privacy relays: blocking them is a policy choice, not right or wrong. Data
# centres: the probe tunnels out through a rented server. Both are left out of the home and mobile groups (build) and
# reported apart, ungraded (evaluation of earlier versions). The list names networks, never addresses.
RELAY_ASNS = {13335: 'Cloudflare (WARP)', 36183: 'Akamai (iCloud Private Relay)'}
HOSTING_ASNS = {16509: 'Amazon', 14618: 'Amazon', 15169: 'Google', 396982: 'Google Cloud', 8075: 'Microsoft', 31898: 'Oracle',
                14061: 'DigitalOcean', 63949: 'Akamai Linode', 20473: 'Vultr', 24940: 'Hetzner', 213230: 'Hetzner Cloud',
                16276: 'OVH', 12876: 'Scaleway', 51167: 'Contabo', 40021: 'Contabo', 60068: 'Datacamp', 212238: 'Datacamp',
                9009: 'M247', 396356: 'Latitude', 36352: 'ColoCrossing', 8100: 'QuadraNet', 53667: 'FranTech',
                197540: 'netcup', 202425: 'IP Volume', 62240: 'Clouvider', 136787: 'TEFINCOM', 141039: 'Tefincom',
                46562: 'Performive', 8560: 'IONOS', 45102: 'Alibaba Cloud', 37963: 'Alibaba Cloud', 132203: 'Tencent Cloud',
                45090: 'Tencent Cloud', 55990: 'Huawei Cloud', 136907: 'Huawei Cloud'}
CONTESTED = os.path.join(ROOT, 'datasets', 'contested.json')
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

    def __init__(self, out=OUT):
        # v2 versions cache per version: a day must never reuse another day's Tor or proxy list.
        self.cache = CACHE if out == OUT else os.path.join(CACHE, 'v2', os.path.relpath(out, V2))
        os.makedirs(self.cache, exist_ok=True)
        self.records = {}
        self.out = out

    def get(self, name, url, public=True):
        # Public snapshots are committed (<version>/sources); everything else is cached.
        committed = os.path.join(self.out, 'sources', name + '.gz')
        path = committed if os.path.exists(committed) else os.path.join(self.cache, name + '.gz')
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
            if public and self.out != OUT:
                path, meta_path = committed, committed + '.json'
                os.makedirs(os.path.dirname(path), exist_ok=True)
            with gzip.open(path, 'wb') as handle:
                handle.write(data)
            with open(meta_path, 'w') as handle:
                json.dump(meta, handle)
        self.records[name] = meta
        return data

    def resolved(self, name, hostnames):
        """DNS A records, resolved once and frozen like any other snapshot."""
        committed = os.path.join(self.out, 'sources', name + '.json')
        path = committed if os.path.exists(committed) or self.out != OUT else os.path.join(self.cache, name + '.json')
        os.makedirs(os.path.dirname(path), exist_ok=True)
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
def item(cohort, label, candidate, source, extra=None):
    return dict(cohort=cohort, label=label, ip=candidate['ip'], family=ipaddress.ip_address(candidate['ip']).version,
                source=source, provider=candidate.get('provider'), country=candidate.get('country'),
                evidence=dict(candidate.get('evidence', {}), **(extra or {})))


def sample_vpn(src, rng, now):
    """commercial_vpn, fresh_vpn and vpn_v6 items, every operator-listed address, and the fresh-rule stats."""
    items = []
    v4, v6 = vpn_candidates(src)
    fresh, fresh_meta = [], {}
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
        items.append(item('fresh_vpn', 'vpn', candidate, candidate['provider']))
    for provider in sorted(v4):
        pool = [c for c in v4[provider] if c['ip'] not in fresh_ips]
        if provider == 'nordvpn':
            pool = [c for c in pool if (now - datetime.datetime.fromisoformat(c['evidence']['created_at']).replace(
                tzinfo=datetime.timezone.utc)).days > 90]
        for candidate in spread(pool, PER_PROVIDER, rng):
            items.append(item('commercial_vpn', 'vpn', candidate, provider))
    pool = [c for provider in sorted(v6) for c in v6[provider]]
    for candidate in spread(pool, TARGETS['vpn_v6'], rng):
        items.append(item('vpn_v6', 'vpn', candidate, candidate['provider']))
    vpn_all = {c['ip'] for provider in v4 for c in v4[provider]} | {c['ip'] for p in v6 for c in v6[p]}
    stats = dict(fresh=fresh_meta, candidates=dict(commercial_vpn={p: len(v) for p, v in v4.items()}, fresh=len(fresh)))
    return items, vpn_all, stats


def sample_tor(src, rng):
    tor = src.get('tor-bulk', 'https://check.torproject.org/torbulkexitlist').decode().split()
    candidates = [dict(ip=ip, provider='tor', country=None) for ip in tor if public_ip(ip)]
    picked = spread(candidates, TARGETS['tor'], rng, key=lambda c: slash24(c['ip'])[:3])
    return [item('tor', 'tor', c, 'torproject-bulk-exit-list') for c in picked], set(tor)


PROXY_LISTS = dict(
    monosans='https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/all.txt',
    proxifly='https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/all/data.txt',
    vakhov='https://raw.githubusercontent.com/vakhov/fresh-proxy-list/master/proxylist.txt')


def sample_proxies(src, rng, exclude, lists=PROXY_LISTS):
    """Open proxies on >= 2 of `lists`, outside `exclude` (Tor exits, VPN servers); every listed address."""
    seen = {}
    for name, url in lists.items():
        for line in src.get(f'proxy-{name}', url).decode('utf-8', 'replace').split():
            host = line.split('://')[-1].rsplit(':', 1)[0].strip('[]')
            if public_ip(host):
                seen.setdefault(host, set()).add(name)
    candidates = [dict(ip=ip, provider='open-proxy', country=None, evidence=dict(listed_by=sorted(names)))
                  for ip, names in seen.items() if len(names) >= 2 and ip not in exclude
                  and ipaddress.ip_address(ip).version == 4]
    picked = spread(candidates, TARGETS['proxy'], rng, key=lambda c: slash24(c['ip'])[:3])
    return [item('proxy', 'proxy', c, 'checked-public-proxy-lists') for c in picked], set(seen), len(candidates)


def sample_ripe(src, rng, date, infrastructure):
    """residential, mobile_cgnat and residential_v6 items from the RIPE Atlas archive of `date`."""
    probes = ripe_probes(src, date)
    conflicts = 0
    residential, mobile, residential6 = [], [], []
    for probe in probes:
        tags = probe_tags(probe)
        if tags & EXCLUDE_TAGS:
            continue
        evidence = dict(probe_id=probe['id'], archive_date=date, tags=sorted(tags & (HOME_TAGS | MOBILE_TAGS)))
        v4ip, v6ip = probe.get('address_v4'), probe.get('address_v6')
        if v4ip in infrastructure or v6ip in infrastructure:
            conflicts += 1
            continue
        if probe.get('asn_v4') in RELAY_ASNS or probe.get('asn_v4') in HOSTING_ASNS:
            v4ip = None  # its IPv4 leaves through a relay or a data centre; its IPv6 may still be a home address
        if probe.get('asn_v6') in RELAY_ASNS or probe.get('asn_v6') in HOSTING_ASNS:
            v6ip = None
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
    items = []
    for cohort, pool, per_asn in (('residential', residential, 2), ('mobile_cgnat', mobile, 3),
                                  ('residential_v6', residential6, 2)):
        for candidate in spread(pool, TARGETS[cohort], rng, per_bucket=per_asn, bucket=lambda c: c['provider']):
            items.append(item(cohort, 'non_vpn', candidate, 'ripe-atlas'))
    return items, conflicts, dict(residential=len(residential), mobile=len(mobile), residential_v6=len(residential6))


def dedupe(items):
    """Keep the first item per address."""
    unique, seen = [], set()
    for entry in items:
        if entry['ip'] not in seen:
            seen.add(entry['ip'])
            unique.append(entry)
    return unique, len(items) - len(unique)


def build():
    """v1 (5 October 2026). Kept for reference: v1 is rebuilt with `materialize`, not built again."""
    rng = random.Random(SEED)
    src = Sources()
    now = datetime.datetime.now(datetime.timezone.utc)
    vpn, vpn_all, vpn_stats = sample_vpn(src, rng, now)
    tor, tor_set = sample_tor(src, rng)
    proxies, proxy_set, proxy_candidates = sample_proxies(src, rng, tor_set | vpn_all)
    ripe, conflicts, ripe_stats = sample_ripe(src, rng, RIPE_ARCHIVE_DATE, tor_set | proxy_set | vpn_all)
    unique, dropped = dedupe(vpn + tor + proxies + ripe)
    for index, entry in enumerate(sorted(unique, key=lambda i: (i['cohort'], i['ip']))):
        entry['id'] = f'{entry["cohort"]}-{index:04d}'
    unique.sort(key=lambda i: i['id'])
    write_outputs(unique, src, dict(vpn_stats, residential_conflicts=conflicts, duplicates_dropped=dropped,
                                    candidates=dict(vpn_stats['candidates'], proxy=proxy_candidates, **ripe_stats)))


# ------------------------------------------------------------------ v2: weekly core, daily Tor and proxies
def stable_id(entry):
    """An id that stays with the address across versions: the cohort and a hash of the address, or of the RIPE Atlas
    probe and address family for volunteers' addresses (their address never enters a public id)."""
    if entry['source'] == 'ripe-atlas':
        key = f'probe-{entry["evidence"]["probe_id"]}-v{entry["family"]}'
    else:
        key = str(ipaddress.ip_address(entry['ip']))
    return f'{entry["cohort"]}-{hashlib.sha256(key.encode()).hexdigest()[:10]}'


def iso_week(date):
    year, week, _ = date.isocalendar()
    return f'{year}-W{week:02d}'


def seed_of(text):
    return int(hashlib.sha256(f'{SEED}-{text}'.encode()).hexdigest()[:12], 16)


def github_changed(url):
    """The last commit date of a raw.githubusercontent.com file, or None for other hosts or on error."""
    prefix = 'https://raw.githubusercontent.com/'
    if not url.startswith(prefix):
        return None
    owner, repo, branch, path = url[len(prefix):].split('/', 3)
    headers = {'User-Agent': USER_AGENT, 'Accept': 'application/vnd.github+json'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = f'Bearer {os.environ["GITHUB_TOKEN"]}'
    request = urllib.request.Request(f'https://api.github.com/repos/{owner}/{repo}/commits?sha={branch}&path={path}&per_page=1',
                                     headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            commits = json.loads(response.read())
    except OSError:
        return None
    return commits[0]['commit']['committer']['date'] if commits else None


def live_lists(now, lists=PROXY_LISTS):
    """The proxy lists whose upstream file changed within STALE_SOURCE_DAYS, and why each other one was left out."""
    keep, dropped = {}, {}
    for name, url in lists.items():
        changed = github_changed(url)
        if changed and (now - datetime.datetime.fromisoformat(changed.replace('Z', '+00:00'))).days > STALE_SOURCE_DAYS:
            dropped[name] = f'unchanged since {changed[:10]}'
        else:
            keep[name] = url
    return keep, dropped


def write_jsonl(path, items, public=True):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as handle:
        for entry in items:
            if public and entry['source'] == 'ripe-atlas':
                entry = dict(entry)
                entry.pop('ip')
                entry['rebuild'] = dict(archive=ripe_archive_url(entry['evidence']['archive_date']),
                                        probe_id=entry['evidence']['probe_id'], field=f'address_v{entry["family"]}')
            handle.write(json.dumps(entry, sort_keys=True) + '\n')


def build_core(date, now):
    """The week's core: VPN servers and home and mobile probes (RIPE Atlas archive of the day before)."""
    week = iso_week(date)
    out = os.path.join(V2, 'core', week)
    src = Sources(out)
    rng = random.Random(seed_of(week))
    vpn, vpn_all, vpn_stats = sample_vpn(src, rng, now)
    archive = (date - datetime.timedelta(days=1)).isoformat()
    # Probes on the day's Tor or proxy lists are dropped as in v1; the lists are read here, not kept in the core.
    tor = {ip for ip in src.get('tor-bulk', 'https://check.torproject.org/torbulkexitlist', public=False).decode().split()}
    ripe, conflicts, ripe_stats = sample_ripe(src, rng, archive, tor | vpn_all)
    items, dropped = dedupe(vpn + ripe)
    for entry in items:
        entry['id'] = stable_id(entry)
    items.sort(key=lambda i: i['id'])
    write_jsonl(os.path.join(PRIVATE_DIR, f'detection-v2-core-{week}.private.jsonl'), items, public=False)
    write_jsonl(os.path.join(out, 'core.public.jsonl'), items)
    manifest = dict(schema=2, name=f'mc-antivpn-bench detection v2 core {week}', week=week, seed=seed_of(week),
                    built_at=now.isoformat(timespec='seconds'), ripe_archive_date=archive,
                    counts=counts_of(items), stats=dict(vpn_stats, residential_conflicts=conflicts, duplicates_dropped=dropped,
                                                        candidates=dict(vpn_stats['candidates'], **ripe_stats)),
                    vpn_addresses=sorted(vpn_all), sources=dict(sorted(src.records.items())))
    with open(os.path.join(out, 'manifest.json'), 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write('\n')
    return week


def counts_of(items):
    counts = {}
    for entry in items:
        counts[entry['cohort']] = counts.get(entry['cohort'], 0) + 1
    return counts


def build_day(date=None):
    """The day's version: this week's core (built first if missing) + the day's Tor exits and proxies."""
    now = datetime.datetime.now(datetime.timezone.utc)
    date = date or now.date()
    week = iso_week(date)
    core_dir = os.path.join(V2, 'core', week)
    if not os.path.exists(os.path.join(core_dir, 'manifest.json')):
        build_core(date, now)
    core_manifest = json.load(open(os.path.join(core_dir, 'manifest.json')))
    if not os.path.exists(core_private(week)):
        materialize_core(week)
    core = [json.loads(line) for line in open(core_private(week))]
    version = date.isoformat()
    out = os.path.join(V2, version)
    if os.path.exists(os.path.join(out, 'manifest.json')):
        print(f'{version} exists; a version is built once')
        return version
    src = Sources(out)
    rng = random.Random(seed_of(version))
    tor, tor_set = sample_tor(src, rng)
    lists, stale_lists = live_lists(now)
    vpn_all = set(core_manifest['vpn_addresses'])
    proxies, _, proxy_candidates = sample_proxies(src, rng, tor_set | vpn_all, lists)
    daily, dropped = dedupe([e for e in tor + proxies if e['ip'] not in vpn_all])
    for entry in daily:
        entry['id'] = stable_id(entry)
    items = sorted(core + daily, key=lambda i: i['id'])
    private = private_path(version)
    write_jsonl(private, items, public=False)
    write_jsonl(os.path.join(out, 'dataset.public.jsonl'), items)
    manifest = dict(schema=2, name=f'mc-antivpn-bench detection v2 {version}', version=version, core=week,
                    seed=seed_of(version), built_at=now.isoformat(timespec='seconds'), counts=counts_of(items),
                    total=len(items), stats=dict(proxy_candidates=proxy_candidates, proxy_lists=sorted(lists),
                                                 proxy_lists_left_out=stale_lists, duplicates_dropped=dropped),
                    sources=dict(sorted(src.records.items())),
                    sha256_private=hashlib.sha256(open(private, 'rb').read()).hexdigest())
    with open(os.path.join(out, 'manifest.json'), 'w') as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write('\n')
    with open(os.path.join(V2, 'CURRENT'), 'w') as handle:
        handle.write(version + '\n')
    print(json.dumps(dict(version=version, core=week, counts=manifest['counts'], total=len(items),
                          proxy_lists_left_out=stale_lists), indent=2))
    return version


def current():
    """The version a run uses: BENCH_DATASET, else the newest v2 day, else v1."""
    if os.environ.get('BENCH_DATASET'):
        return os.environ['BENCH_DATASET']
    path = os.path.join(V2, 'CURRENT')
    return open(path).read().strip() if os.path.exists(path) else 'v1'


def version_dir(version):
    return OUT if version == 'v1' else os.path.join(V2, version)


def private_path(version):
    return os.path.join(PRIVATE_DIR, 'detection-v1.private.jsonl' if version == 'v1' else f'detection-v2-{version}.private.jsonl')


def public_items(version):
    """A version's public items (no volunteer addresses)."""
    path = os.path.join(version_dir(version), 'dataset.public.jsonl')
    return [json.loads(line) for line in open(path)] if os.path.exists(path) else []


_STABLE = {}


def stable_ids(version):
    """{id in that version: stable id}. v2 ids are stable already; v1's are translated, so runs on v1 and v2 compare
    on the addresses they share."""
    if version not in _STABLE:
        _STABLE[version] = {e['id']: (stable_id(e) if version == 'v1' else e['id']) for e in public_items(version)}
    return _STABLE[version]


def core_of(version):
    """The core a version is built on: 'v1' for v1, else its ISO week. Versions with the same core share every VPN
    server and probe."""
    if version == 'v1':
        return 'v1'
    path = os.path.join(version_dir(version), 'manifest.json')
    return json.load(open(path)).get('core', version) if os.path.exists(path) else version


def ungraded(entry):
    """(cohort, reason) for a home or mobile item that leaves through a privacy relay or a data centre, else None."""
    if not entry or entry.get('source') != 'ripe-atlas':
        return None
    asn = (entry.get('evidence') or {}).get('asn')
    if asn in RELAY_ASNS:
        return 'privacy_relay', f'leaves through {RELAY_ASNS[asn]}'
    if asn in HOSTING_ASNS:
        return 'tunnel', f'leaves through a data centre ({HOSTING_ASNS[asn]})'
    return None


_BY_ID = {}


def items_by_id(version):
    if version not in _BY_ID:
        _BY_ID[version] = {e['id']: e for e in public_items(version)}
    return _BY_ID[version]


_ALL = {}


def by_stable_id():
    """Stable id -> public entry over v1 and every v2 day."""
    if not _ALL:
        versions = ['v1'] + sorted(d for d in (os.listdir(V2) if os.path.isdir(V2) else [])
                                   if os.path.exists(os.path.join(V2, d, 'dataset.public.jsonl')))
        for version in versions:
            ids = stable_ids(version)
            for native, entry in items_by_id(version).items():
                _ALL.setdefault(ids[native], entry)
    return _ALL


def contested():
    """Stable id -> entry of every contested address (datasets/contested.json): a label shown not to hold when it was
    measured, with evidence. Contested addresses count for no one."""
    if not os.path.exists(CONTESTED):
        return {}
    return {e['id']: e for e in json.load(open(CONTESTED))['addresses']}


def run_version(manifest):
    """The dataset version a run used (runs before v2 recorded none: v1)."""
    return ((manifest or {}).get('environment') or {}).get('dataset') or 'v1'


def core_private(week):
    return os.path.join(PRIVATE_DIR, f'detection-v2-core-{week}.private.jsonl')


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


def with_addresses(public_path, src):
    """The items of a public file with the volunteers' addresses put back from the RIPE Atlas archive."""
    archives, private = {}, []
    for line in open(public_path):
        entry = json.loads(line)
        rebuild = entry.pop('rebuild', None)
        if rebuild:
            date = entry['evidence']['archive_date']
            if date not in archives:
                payload = json.loads(src.get(f'ripe-archive-{date}', rebuild['archive'], public=False))
                archives[date] = {p['id']: p for p in payload['results']}
            entry['ip'] = archives[date][rebuild['probe_id']][rebuild['field']]
        private.append(entry)
    return private


def materialize_core(week):
    out = os.path.join(V2, 'core', week)
    write_jsonl(core_private(week), with_addresses(os.path.join(out, 'core.public.jsonl'), Sources(out)), public=False)


def materialize(version=None):
    """Rebuild a version's private dataset (with addresses) from its public file + the RIPE Atlas archive."""
    version = version or current()
    if version != 'v1':
        out = version_dir(version)
        path = private_path(version)
        write_jsonl(path, with_addresses(os.path.join(out, 'dataset.public.jsonl'), Sources(out)), public=False)
        expected = json.load(open(os.path.join(out, 'manifest.json')))['sha256_private']
        actual = hashlib.sha256(open(path, 'rb').read()).hexdigest()
        print(json.dumps(dict(version=version, sha256=actual, matches_manifest=actual == expected)))
        if actual != expected:
            sys.exit(f'materialized dataset {version} does not match its manifest hash')
        return
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
    command, args = (sys.argv[1:] or [''])[0], sys.argv[2:]
    if command == 'build':
        build()
    elif command == 'build-day':
        build_day(datetime.date.fromisoformat(args[0]) if args else None)
    elif command == 'materialize':
        materialize(args[0] if args else None)
    elif command == 'current':
        print(current())
    else:
        sys.exit('usage: python3 -m bench.dataset build-day [YYYY-MM-DD] | materialize [version] | current')
