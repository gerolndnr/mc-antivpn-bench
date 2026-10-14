"""Home addresses from consumer ISPs' own customer pools: a second, stricter ground truth for real players.

A detection test needs only the address, not a device behind it: the benchmark hands the address to the plugin. So a
home address need not come from a volunteer. It can be drawn from a consumer ISP's dynamic customer pool, when the
ISP itself says that is what the range is. An address is admitted only when every piece of evidence agrees, none of it
from a detection service under test:

1. the network serves end users: at least MIN_USERS in APNIC's per-AS user estimates;
2. the ISP's reverse DNS for the address names a customer pool (dip, dyn, pool, dsl, cable, ftth, customer, cpe …)
   and nothing that speaks of a business line or a server (static, business, server, host, mail …);
3. the name is under the ISP's own customer domain: the domain most of the network's sampled names share, so a
   business customer with its own reverse DNS falls out;
4. the registry record of the range does not speak of hosting, business or static lines.

Connection Guard Intel is a service under test, so its lists never decide admission: each address records which Intel
lists name it (`intel`), for the report only. (Until 14 Oct 2026 Intel-listed addresses were left out, which favoured
Connection Guard.)

The strata go from easy to hard. The hard ones are where services judge a home line by its company, its size, its
crowd or its odd location instead of by the line:
- home_large, home_small: the biggest and regional consumer ISPs of the countries below;
- brand_trap: home lines of companies better known for cloud, hosting or transit (Google Fiber, OVH Telecom, Init7 …).
  These ISPs name customer lines by the address alone (a-b-c-d.googlefiber.net), so here a name that encodes the
  address under the ISP's own customer domain also counts, never one that speaks of business or servers;
- small_isp: networks with 1,000 to 50,000 users, where services have little data;
- mobile, mobile_cgnat: mobile operators; mobile_cgnat are the large ones in India and Indonesia, where hundreds of
  real players share one address (the reputation trap);
- satellite: Starlink's published customer ranges and Viasat's customer names (cust.exede.net);
- student_housing: ranges that the registry names as student residences (RIPE full-text search).

Addresses are random addresses of these pools: whether one is in use right now is unknown, and to the services under
test it is as unknown as to us. They are kept private like volunteers' addresses (cache/private).

  PYTHONPATH=harness python3 -m bench.pools build [per_asn] [stratum,...|hard]   # writes cache/private/pools-<date>.jsonl
"""
import collections
import datetime
import ipaddress
import json
import os
import random
import re
import socket
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PRIVATE = os.path.join(ROOT, 'cache', 'private')
MIN_USERS = 1_000_000
# Countries where most Minecraft servers that use an anti-VPN plugin stand (FoxGate's bStats, 14 Oct 2026); in each,
# the three networks with the most users in APNIC's estimates.
COUNTRIES = ['US', 'DE', 'FR', 'SG', 'PL', 'BR', 'IN', 'TR', 'FI', 'IT', 'CA', 'JP', 'NL', 'GB', 'HU', 'SE', 'TH', 'CZ',
             'VN', 'ES', 'ID', 'AE']
CUSTOMER = re.compile(r'(^|[.\-_\d])(dip|dyn|dynamic|dhcp|pool|dsl|adsl|vdsl|xdsl|cable|catv|docsis|ftth|fttx|fttb|fiber|'
                      r'fibre|fibra|bb|broadband|customer|cust|client|subscriber|sub|res|resi|residential|home|cpe|ppp|'
                      r'pppoe|user|users|hsd\d*|mobile|gprs|lte|cgnat|wireless|dialup|dial|adsl\d*)([.\-_\d]|$)',
                      re.I)
BUSINESS = re.compile(r'(^|[.\-_\d])(static|stat|business|biz|corp|corporate|enterprise|ent|server|srv|host|hosting|'
                      r'vps|colo|dc|dedicated|cloud|mail|smtp|mx|ns\d*|www|office|gw|gateway|router|core|bgp|pe\d*)'
                      r'([.\-_\d]|$)', re.I)
HOSTING_RANGE = re.compile(r'hosting|data.?cent|colo|server|business|corporate|enterprise|static|\bdc\b', re.I)


def fetch_json(url, timeout=60, attempts=3):
    import time
    request = urllib.request.Request(url, headers={'User-Agent': 'mc-antivpn-bench pools (github.com/gerolndnr/mc-antivpn-bench)'})
    for attempt in range(attempts):
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode('latin-1'))
        except (OSError, ValueError):
            if attempt == attempts - 1:
                raise
            time.sleep(3 * (attempt + 1))


def networks(apnic):
    """The three networks with the most users in each country, with at least MIN_USERS."""
    by = collections.defaultdict(list)
    for row in apnic['Data']:
        if row['CC'] in COUNTRIES and row['Users'] >= MIN_USERS:
            by[row['CC']].append(row)
    return [dict(cc=cc, asn=r['AS'], name=r['Description'], users=r['Users'])
            for cc in COUNTRIES for r in sorted(by[cc], key=lambda r: -r['Users'])[:3]]


def registered_domain(name):
    """'p5b0a1c2d.dip0.t-ipconnect.de' -> 't-ipconnect.de' (last two labels; three for co.uk-style suffixes)."""
    labels = name.rstrip('.').lower().split('.')
    if len(labels) >= 3 and len(labels[-2]) <= 3 and len(labels[-1]) == 2:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def ptr(ip):
    """The address's reverse name, or None. dig with a short timeout: the system resolver can wait 30 s for a missing name."""
    import subprocess
    try:
        out = subprocess.run(['dig', '+short', '+time=2', '+tries=1', '-x', ip], capture_output=True, text=True, timeout=6).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    # A name inside in-addr.arpa (a CNAME of a delegated block) is no name the ISP gave.
    names = [line.rstrip('.') for line in out.splitlines() if line and not line.startswith(';') and not line.rstrip('.').endswith('in-addr.arpa')]
    return names[0] if names else None


def classify_name(name):
    """'customer', 'business' or None (no evidence either way)."""
    if not name:
        return None
    if BUSINESS.search(name):
        return 'business'
    if CUSTOMER.search(name):
        return 'customer'
    return None


def encodes(ip, name):
    """True when the reverse name spells the address itself (decimal octets in order, or the 8 hex digits): a name the
    ISP generated for every address of a pool."""
    octets = ip.split('.')
    if re.search(r'(^|\D)' + r'\D{1,3}'.join(octets) + r'(\D|$)', name) or re.search(r'(^|\D)' + r'\D{1,3}'.join(reversed(octets)) + r'(\D|$)', name):
        return True
    return ''.join(f'{int(o):02x}' for o in octets) in name.lower()


def admit(samples, range_names, range_rule=None, encoded=False):
    """Strict admission from one network's sampled (ip, reverse name) pairs. Returns admitted entries and reasons.
    With `encoded`, a name that spells the address (and says nothing of business or servers) counts as a pool name."""
    named = [(ip, n) for ip, n in samples if n]
    domains = collections.Counter(registered_domain(n) for _, n in named)
    home = domains.most_common(1)[0][0] if domains else None
    out, reasons = [], collections.Counter()
    for ip, name in samples:
        kind = classify_name(name)
        if encoded and kind is None and name and encodes(ip, name):
            kind = 'customer'
        if name is None:
            reasons['no reverse name'] += 1
        elif kind != 'customer':
            reasons['reverse name not a customer pool' if kind is None else 'reverse name speaks of business or server'] += 1
        elif registered_domain(name) != home:
            reasons["not under the ISP's customer domain"] += 1
        elif (range_rule or HOSTING_RANGE).search(range_names(ip) or ''):
            reasons['registry record speaks of hosting or business'] += 1
        else:
            m = CUSTOMER.search(name)
            out.append(dict(ip=ip, ptr_domain=home, ptr_kind=m.group(2).lower() if m else 'address-name'))
    return out, reasons


def announced(asn):
    data = fetch_json(f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}')['data']
    return [ipaddress.ip_network(p['prefix']) for p in data.get('prefixes', []) if ':' not in p['prefix']]


def random_addresses(prefixes, n, rng):
    """Addresses spread over the network's announced IPv4 space, weighted by size, never .0 or .255."""
    prefixes = [p for p in prefixes if p.prefixlen <= 24]
    weights = [p.num_addresses for p in prefixes]
    out = set()
    while prefixes and len(out) < n:
        p = rng.choices(prefixes, weights)[0]
        ip = p.network_address + rng.randrange(1, p.num_addresses - 1)
        if ip.packed[-1] not in (0, 255):
            out.add(str(ip))
    return sorted(out)


def intel_lists(intel_dir):
    by = {}
    for name in ('vpn', 'proxy', 'tor', 'relay', 'hosting'):
        path = os.path.join(intel_dir, f'{name}.txt')
        if os.path.exists(path):
            by[name] = [ipaddress.ip_network(l.split()[0]) for l in open(path) if l.strip() and not l.startswith('#')]

    def lists_of(ip):
        a = ipaddress.ip_address(ip)
        return [name for name, nets in by.items() if any(n.version == a.version and a in n for n in nets)]
    return lists_of


# Mobile-only operators (their own description or APNIC's): every address is a phone or a mobile router behind CGNAT.
MOBILE_ASNS = {21928: ('T-Mobile USA', 'US'), 23693: ('Telkomsel', 'ID'), 131445: ('AIS 3G', 'TH'), 45143: ('Singtel Mobile', 'SG'),
               45609: ('Bharti Airtel mobility', 'IN'), 12912: ('T-Mobile Polska', 'PL'), 39603: ('Play / P4', 'PL'),
               16135: ('Turkcell', 'TR')}
MOBILE_RANGE = re.compile(r'mobile|cellular|gprs|umts|lte|3g|4g|5g|ggsn|apn|cgnat|wireless|mobility|t-mobile|tmo\d', re.I)
# Large mobile operators where hundreds of real players share one address behind carrier-grade NAT.
CGNAT_ASNS = {55836: ('Reliance Jio', 'IN'), 38266: ('Vodafone Idea', 'IN'), 4761: ('Indosat Ooredoo', 'ID'), 24203: ('XL Axiata', 'ID')}
# Home lines sold by companies better known for cloud, hosting or transit: hard for services that judge by the company.
BRAND_TRAP = {35540: ('OVH Telecom', 'FR'), 16591: ('Google Fiber', 'US'), 19165: ('Webpass (Google Fiber)', 'US'),
              13030: ('Init7 / Fiber7', 'CH'), 209: ('CenturyLink / Lumen', 'US'), 8881: ('1&1 Versatel', 'DE'),
              46375: ('Sonic', 'US'), 20712: ('Andrews & Arnold', 'GB')}
# Satellite ISPs whose reverse names mark consumer terminals (HughesNet's hnremote.net also covers business VSATs).
SATELLITE_NAMED = {7155: ('Viasat (Exede)', 'US')}
# Words in a registry record that name a student residence; ranges that also speak of servers are left out.
HOUSING_QUERIES = ['STUDENTENWOHNHEIM', 'WOHNHEIM', 'RESNET', 'STUDENT HOUSING', 'HALLS OF RESIDENCE', 'DORMITORY', 'AKADEMIK',
                   'KOLEJ', 'STUDENTSKY DOMOV', 'STUDENTENHUIS']
HOUSING = re.compile(r'wohnheim|stuwo|resnet|student.?(housing|residen|village|hall)|halls? of residence|dorm|akademik|kolej|'
                     r'studentsk|studentenhuis|kollegium|kolegij', re.I)
FULLTEXT = 'https://apps.db.ripe.net/db-web-ui/api/rest/fulltextsearch/select?q={}&rows=100&start=0&wt=json'
# Cloudflare: its "users" are WARP, a relay. (APNIC also counts VPN users in hosting networks; a stratum of ISPs with
# hosting-sounding names admitted nothing from the 40 largest on 14 Oct 2026, so there is none.)
NOT_ISP = {13335}
# Campus, research and transit networks are no home ISPs, whatever their reverse names say (14 Oct 2026: a university
# network's dhcp pool, which ProxyCheck reads as a VPN, and a transit carrier slipped into small_isp).
NOT_HOME_NAME = re.compile(r'universit|college|school|research|rechenzentrum|\bedu|academ|science|backbone|transit|\bgov', re.I)
STARLINK_GEOFEED = 'https://geoip.starlinkisp.net/feed.csv'
from .access import HOSTING_NAME  # noqa: E402
from .dataset import HOSTING_ASNS  # noqa: E402
STRATA = ['home_large', 'home_small', 'brand_trap', 'small_isp', 'mobile', 'mobile_cgnat', 'satellite',
          'student_housing']
HARD = STRATA[2:]


def build(per_asn=5, intel_dir=None, seed=None, strata=None, log=sys.stderr):
    """Draws the strata (STRATA, or the given subset) and writes cache/private/pools-<date>.jsonl. Each stratum keeps
    the same strictness; a network or range without evidence is left out, never guessed."""
    strata = strata or STRATA
    date = datetime.date.today().isoformat()
    rng = random.Random(seed or date)
    apnic = fetch_json('https://stats.labs.apnic.net/cgi-bin/aspop?f=j')
    users = collections.Counter()
    names, home_cc = {}, {}
    for row in apnic['Data']:
        users[row['AS']] += row['Users']
        names.setdefault(row['AS'], row['Description'])
        home_cc.setdefault(row['AS'], row['CC'])
    lists_of = intel_lists(intel_dir) if intel_dir else (lambda ip: [])
    whois_cache = {}

    def range_names(ip):
        if ip not in whois_cache:
            try:
                data = fetch_json(f'https://stat.ripe.net/data/whois/data.json?resource={ip}')['data']
                whois_cache[ip] = ' '.join(x['value'] for rec in data.get('records', []) for x in rec
                                           if x['key'] in ('netname', 'descr', 'NetName', 'OrgName'))
            except Exception:  # noqa: BLE001
                whois_cache[ip] = ''
        return whois_cache[ip]

    def say(*parts):
        print(*parts, file=log, flush=True)

    items, stats = [], {}
    # The hard strata are what makes this group hard, so they get more room than one network's five.
    caps = dict(brand_trap=2 * per_asn, mobile_cgnat=2 * per_asn, satellite=6 * per_asn, student_housing=8 * per_asn)

    def keep(stratum, asn, cc, network, admitted, cap=None):
        rng.shuffle(admitted)
        for entry in admitted[:cap or caps.get(stratum, per_asn)]:
            items.append(dict(entry, cohort=f'pool_{stratum}', stratum=stratum, label='non_vpn', asn=asn, country=cc,
                              network=network, intel=lists_of(entry['ip'])))

    def by_reverse_name(stratum, asn, cc, network, sample=40, encoded=False, rule=HOSTING_RANGE):
        try:
            prefixes = announced(asn)
        except Exception as error:  # noqa: BLE001
            stats[f'{stratum}/AS{asn}'] = dict(error=str(error)[:80])
            return
        candidates = random_addresses(prefixes, sample, rng)
        with ThreadPoolExecutor(32) as pool:
            samples = list(zip(candidates, pool.map(ptr, candidates)))
        passed = [ip for ip, n in samples if classify_name(n) == 'customer' or (encoded and n and classify_name(n) is None and encodes(ip, n))]
        with ThreadPoolExecutor(8) as pool:  # warm the whois cache for the names that passed the name checks
            list(pool.map(range_names, passed))
        admitted, reasons = admit(samples, range_names, rule, encoded=encoded)
        keep(stratum, asn, cc, network, admitted)
        stats[f'{stratum}/AS{asn}'] = dict(cc=cc, sampled=len(samples), admitted=len(admitted), rejected=dict(reasons))
        say(f'{stratum:18} AS{asn:<7} {cc} {network[:34]:34} admitted {len(admitted):2}/{len(samples)}')

    def by_range_record(stratum, operators, sample=30):
        """Operators whose every customer is a phone or a home router: random addresses whose range record speaks of
        neither companies nor hosting."""
        for asn, (network, cc) in operators.items():
            try:
                candidates = random_addresses(announced(asn), sample, rng)
            except Exception as error:  # noqa: BLE001
                stats[f'{stratum}/AS{asn}'] = dict(error=str(error)[:80])
                continue
            with ThreadPoolExecutor(8) as pool:
                records = list(pool.map(range_names, candidates))
            admitted, reasons = [], collections.Counter()
            for ip, record in zip(candidates, records):
                if not record:
                    reasons['no range record'] += 1
                elif HOSTING_RANGE.search(record) or re.search(r'kurumsal|corporate|enterprise|business|idc|data.?cent', record, re.I):
                    reasons['range record speaks of companies or hosting'] += 1
                elif not (MOBILE_RANGE.search(record) or users[asn] >= MIN_USERS):
                    reasons['range record does not speak of mobile'] += 1
                else:
                    admitted.append(dict(ip=ip, evidence=f'{stratum} operator; range record: ' + record[:60]))
            keep(stratum, asn, cc, network, admitted)
            stats[f'{stratum}/AS{asn}'] = dict(sampled=len(candidates), admitted=len(admitted), rejected=dict(reasons))
            say(f'{stratum:18} AS{asn:<7} {network[:40]:40} admitted {len(admitted):2}/{len(candidates)}')

    socket.setdefaulttimeout(4)
    by_cc = collections.defaultdict(list)
    for row in apnic['Data']:
        if row['CC'] in COUNTRIES and row['AS'] not in MOBILE_ASNS and row['AS'] not in CGNAT_ASNS:
            by_cc[row['CC']].append(row)
    hosting_like = lambda asn, name: (HOSTING_NAME.search(name) or NOT_HOME_NAME.search(name)  # noqa: E731
                                      or asn in HOSTING_ASNS or asn in NOT_ISP)
    for cc in COUNTRIES:
        top = sorted(by_cc[cc], key=lambda r: -r['Users'])
        # home_large: the three biggest networks per country (>= 1 million users).
        if 'home_large' in strata:
            for r in [r for r in top if r['Users'] >= MIN_USERS][:3]:
                by_reverse_name('home_large', r['AS'], cc, r['Description'])
        # home_small: regional ISPs with 50,000 to 1 million users, two per country.
        if 'home_small' in strata:
            for r in [r for r in top if 50_000 <= r['Users'] < MIN_USERS and not hosting_like(r['AS'], r['Description'])][:2]:
                by_reverse_name('home_small', r['AS'], cc, r['Description'])
        # small_isp: 1,000 to 50,000 users, eight per country at random. Few small ISPs name their pools, so most
        # networks admit nothing (14 Oct 2026: 3 of 88).
        if 'small_isp' in strata:
            small = [r for r in top if 1_000 <= r['Users'] < 50_000 and not hosting_like(r['AS'], r['Description'])]
            for r in rng.sample(small, min(len(small), 8)):
                by_reverse_name('small_isp', r['AS'], cc, r['Description'], sample=30)
    if 'brand_trap' in strata:
        for asn, (network, cc) in BRAND_TRAP.items():
            by_reverse_name('brand_trap', asn, cc, network, sample=60, encoded=True,
                            rule=re.compile(r'hosting|data.?cent|colo|server|corporate|enterprise|business', re.I))
    if 'mobile' in strata:
        by_range_record('mobile', MOBILE_ASNS)
    if 'mobile_cgnat' in strata:
        by_range_record('mobile_cgnat', CGNAT_ASNS, sample=40)
    if 'satellite' in strata:
        for asn, (network, cc) in SATELLITE_NAMED.items():
            by_reverse_name('satellite', asn, cc, network, sample=60)
        # Starlink's own published customer ranges (geofeed, RFC 8805).
        request = urllib.request.Request(STARLINK_GEOFEED, headers={'User-Agent': 'mc-antivpn-bench pools'})
        feed = [line.split(',') for line in urllib.request.urlopen(request, timeout=60).read().decode().splitlines()
                if line and not line.startswith('#')]
        v4 = [(ipaddress.ip_network(f[0]), f[1]) for f in feed if ':' not in f[0]]
        picked = rng.sample(v4, min(len(v4), per_asn * 6))
        admitted = [dict(ip=str(net.network_address + rng.randrange(1, max(2, net.num_addresses - 1))),
                         evidence=f'Starlink geofeed {net} ({cc})', geo_cc=cc) for net, cc in picked]
        keep('satellite', 14593, 'XX', 'SpaceX Starlink', admitted)
        stats['satellite/AS14593'] = dict(sampled=len(picked), admitted=len(admitted))
    if 'student_housing' in strata:
        # Ranges the registry itself names as student residences; one address per range, two ranges per maintainer.
        ranges, seen = [], set()
        for query in HOUSING_QUERIES:
            try:
                docs = fetch_json(FULLTEXT.format(urllib.request.quote(query)))['result'].get('docs', [])
            except Exception:  # noqa: BLE001
                continue
            for doc in docs:
                fields = collections.defaultdict(list)
                for entry in doc['doc']['strs']:
                    if 'value' in entry['str']:
                        fields[entry['str']['name']].append(entry['str']['value'])
                if fields['object-type'] != ['inetnum'] or fields['inetnum'][0] in seen:
                    continue
                text = ' '.join(fields['netname'] + fields['descr'])
                if not HOUSING.search(text) or HOSTING_RANGE.search(text):
                    continue
                seen.add(fields['inetnum'][0])
                ranges.append((fields['inetnum'][0], text, (fields['mnt-by'] or ['?'])[0], (fields['country'] or ['XX'])[0]))
        rng.shuffle(ranges)
        per_mnt, admitted = collections.Counter(), []
        for inetnum, text, mnt, cc in ranges:
            first, last = (ipaddress.ip_address(x.strip()) for x in inetnum.split('-'))
            size = int(last) - int(first) + 1
            if per_mnt[mnt] >= 2 or size < 4:
                continue
            ip = ipaddress.ip_address(int(first) + rng.randrange(1, size - 1))
            if ip.packed[-1] in (0, 255):
                continue
            per_mnt[mnt] += 1
            admitted.append(dict(ip=str(ip), evidence='registry: ' + text[:70], maintainer=mnt, range_cc=cc))
        keep('student_housing', None, 'XX', 'student residences (RIPE)', admitted)
        stats['student_housing'] = dict(ranges=len(ranges), admitted=len(admitted), maintainers=len(per_mnt))
        say(f'student_housing    {len(ranges)} ranges, {len(per_mnt)} maintainers, admitted {len(admitted)}')
    items_by = collections.Counter(i['stratum'] for i in items)
    os.makedirs(PRIVATE, exist_ok=True)
    part = '' if strata == STRATA else '-hard' if strata == HARD else '-' + '-'.join(strata)
    path = os.path.join(PRIVATE, f'pools-{date}{part}.jsonl')
    with open(path, 'w') as handle:
        for i, entry in enumerate(items):
            handle.write(json.dumps(dict(entry, id=f"pool-{entry['stratum']}-{i:04d}"), sort_keys=True) + '\n')
    with open(path.replace('.jsonl', '.stats.json'), 'w') as handle:
        json.dump(stats, handle, indent=1, sort_keys=True)
    say(json.dumps(dict(path=path, items=len(items), strata=dict(items_by),
                        intel_listed=sum(bool(i['intel']) for i in items)), indent=1))
    return path


if __name__ == '__main__':
    command, args = (sys.argv[1:] or [''])[0], sys.argv[2:]
    if command == 'build':
        # build [per_asn] [stratum,stratum,...|hard]
        chosen = args[1].split(',') if len(args) > 1 and args[1] != 'hard' else (HARD if len(args) > 1 else None)
        build(int(args[0]) if args else 5, intel_dir=os.environ.get('INTEL_LISTS'), strata=chosen)
    else:
        sys.exit('usage: python3 -m bench.pools build [per_asn] [stratum,...|hard]')
