"""Evidence that a volunteer's probe reaches the internet through an access network (home or mobile customers).

A RIPE Atlas tag such as `home` says where the probe stands, not which network its address belongs to: a probe at
home can leave through an IPv6 tunnel, a rented server or a data-centre provider's business line (14 Oct 2026: probes
tagged `home` in IMAQLIQ's data centre, at HZ Hosting, at Inleed and behind Hurricane Electric tunnels). So a home or
mobile address counts as a real player only with evidence about its network that is independent of the detection
services under test:

- the network serves end users: at least MIN_USERS in APNIC's per-AS user estimates, or PeeringDB type Cable/DSL/ISP;
- a network whose name speaks of hosting, cloud or a data centre counts only for an address range that is named as a
  customer range (DSL, PPPoE, broadband, pool …);
- a range named as a data centre, hosting or colocation range never counts;
- tunnels (Hurricane Electric's tunnel broker, 6to4, Teredo) and probes tagged `ipv6-tunnel`, `vm` or `hackerspace`
  never count.

Sources (both re-usable with attribution): APNIC "Estimates of user population per AS"
(https://stats.labs.apnic.net/aspop), PeeringDB network records (https://www.peeringdb.com), and the registry's
whois record of the address range via RIPEstat.
"""
import collections
import hashlib
import ipaddress
import json
import os
import re

APNIC_URL = 'https://stats.labs.apnic.net/cgi-bin/aspop?f=j'
PEERINGDB_URL = 'https://www.peeringdb.com/api/net?fields=asn,info_type,info_types,name'
WHOIS_URL = 'https://stat.ripe.net/data/whois/data.json?resource={}'

MIN_USERS = 1000
EXCLUDE_TAGS = {'ipv6-tunnel', 'vm', 'hackerspace'}
TUNNELS = [ipaddress.ip_network(n) for n in ('2001:470::/32', '2002::/16', '2001::/32', '192.88.99.0/24')]
HOSTING_NAME = re.compile(r'data.?cent(er|re)|hosting|cloud|\bcolo(cation)?\b|\bservers?\b|\bvps\b|dedicated', re.I)
HOSTING_RANGE = re.compile(r'(^|[-_ ])(DC|HOSTING|COLO|SERVERS?|VPS|CLOUD|DATACENT\w*)([-_ ]|$)', re.I)
CUSTOMER_RANGE = re.compile(r'DSL|PPPOE|BROADBAND|CUSTOMER|DYNAMIC|POOL|SUBSCRIBER|\bUSERS?\b|CLIENT|FTTH|FTTX|CABLE|'
                            r'RESIDENTIAL|MOBILE|\bLTE\b|GPON|\bBNG\b|\bHOME\b', re.I)


def apnic_users(data):
    """APNIC's estimate has one row per AS and country; an AS's users are their sum."""
    users, names = collections.Counter(), {}
    for row in data.get('Data', []):
        users[row['AS']] += row.get('Users') or 0
        names.setdefault(row['AS'], row.get('Description') or '')
    return users, names


def peeringdb_types(data):
    out = {}
    for net in data.get('data', []):
        types = set(net.get('info_types') or ([net['info_type']] if net.get('info_type') else []))
        out[net['asn']] = (types, net.get('name') or '')
    return out


def range_names(whois):
    """Netname, descr and org names of the address range from a RIPEstat whois answer."""
    data = whois.get('data') or {}
    return ' '.join(x.get('value', '') for record in data.get('records', []) for x in record
                    if x.get('key') in ('netname', 'descr', 'NetName', 'OrgName'))


class AccessNetworks:
    """Network-level evidence, loaded once per build. `whois` fetches a range's record for an address."""

    def __init__(self, apnic, peeringdb, whois):
        self.users, self.names = apnic_users(apnic)
        self.peeringdb = peeringdb_types(peeringdb)
        self.whois = whois

    @classmethod
    def from_sources(cls, src):
        # Cached, not committed: the manifest keeps each snapshot's hash and time (PeeringDB's terms do not clearly
        # allow republishing its data in bulk).
        apnic = json.loads(src.get('apnic-aspop', APNIC_URL, public=False).decode('latin-1'))
        peeringdb = json.loads(src.get('peeringdb-net', PEERINGDB_URL, public=False))
        # A whois request names a volunteer's address, so it bypasses Sources (whose records go into the public
        # manifest): answers are cached privately, and the manifest only counts them.
        from .dataset import fetch_with_retries
        cache = os.path.join(src.cache, 'whois')
        os.makedirs(cache, exist_ok=True)
        counter = src.records.setdefault('ripestat-whois', dict(source='RIPEstat whois of each sampled home or mobile '
                                                                       'address (cached privately)', lookups=0, public=False))

        def whois(ip):
            path = os.path.join(cache, hashlib.sha256(ip.encode()).hexdigest()[:24] + '.json')
            if not os.path.exists(path):
                try:
                    data = fetch_with_retries(WHOIS_URL.format(ip), attempts=3)
                except Exception:  # noqa: BLE001 - no record is no evidence, not a crash
                    return {}
                with open(path, 'wb') as handle:
                    handle.write(data)
            counter['lookups'] += 1
            try:
                return json.load(open(path))
            except ValueError:
                return {}
        return cls(apnic, peeringdb, whois)

    def network(self, asn):
        """'access', 'mixed' (end users, but a hosting-sounding name or type) or 'none' (no evidence of end users)."""
        types, pdb_name = self.peeringdb.get(asn, (set(), ''))
        name = self.names.get(asn) or pdb_name
        end_users = self.users[asn] >= MIN_USERS or 'Cable/DSL/ISP' in types
        if not end_users:
            return 'none'
        hosting = bool(HOSTING_NAME.search(name)) or (bool(types & {'Content', 'Enterprise'}) and 'Cable/DSL/ISP' not in types)
        return 'mixed' if hosting else 'access'

    def cheap(self, asn, ip, tags):
        """The checks that need no request: tags, tunnels, the network. None when the address may still count."""
        if tags & EXCLUDE_TAGS:
            return 'tag ' + '/'.join(sorted(tags & EXCLUDE_TAGS))
        address = ipaddress.ip_address(ip)
        if any(address in n for n in TUNNELS if n.version == address.version):
            return 'tunnel range'
        if self.network(asn) == 'none':
            return 'no evidence of end users on the network'
        return None

    def check(self, asn, ip, tags):
        """(reason it does not count or None, public evidence)."""
        types, _ = self.peeringdb.get(asn, (set(), ''))
        evidence = dict(apnic_users=self.users[asn], peeringdb=sorted(types))
        reason = self.cheap(asn, ip, tags)
        if reason:
            return reason, evidence
        names = range_names(self.whois(ip))
        if HOSTING_RANGE.search(names):
            return 'hosting or data-centre range', evidence
        network = self.network(asn)
        if network == 'mixed' and not CUSTOMER_RANGE.search(names):
            return 'hosting network without a customer range', evidence
        evidence['network'] = 'customer range in a mixed network' if network == 'mixed' else 'access network'
        return None, evidence
