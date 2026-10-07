"""Family `providers`: the detection services themselves, without any plugin.

Every dataset address is sent straight to each service, keyless unless a key is configured, at that service's
own rate limit and daily quota. A service that runs out of quota answers nothing for the remaining addresses
(`not_queried`), exactly as it would on a server. The answers are then replayed through whole lookup chains
(Connection Guard's default and variants), so a chain change can be measured before it ships.

Verdicts follow the plugins' reading of each answer: a VPN, proxy or Tor flag is `positive`, explicit clean flags
are `negative`, and hosting alone or missing flags are `unknown` (the chain asks the next service).

  python3 -m bench run providers --run-id ID [--services a,b] [--limit N]

Public: results/<run>/providers/ (subject ids only). Private: cache/private/runs/<run>/providers/raw.jsonl.
"""
import concurrent.futures as cf
import ipaddress
import json
import math
import os
import random
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request

from . import scenarios
from .score import REFUSAL_WEIGHT, SPEED_POINTS_MAX, SPEED_POINTS_PER_S, score, score_range

UA = 'mc-antivpn-bench provider comparison (https://github.com/gerolndnr/mc-antivpn-bench)'
INTEL = 'https://intel.connectionguard.net/'
POSITIVE, NEGATIVE, UNKNOWN = 'positive', 'negative', 'unknown'
q = urllib.parse.quote


def _flag(value):
    if isinstance(value, dict):
        value = value.get('detected')
    if isinstance(value, str):
        return value.strip().lower() in ('true', 'yes', '1', 'y')
    return None if value is None else bool(value)


def verdict(vpn=None, proxy=None, tor=None, hosting=None):
    """The plugins' reading: any explicit VPN/proxy/Tor flag decides; hosting alone is review evidence only."""
    flags = dict(vpn=vpn, proxy=proxy, tor=tor, hosting=hosting)
    if vpn or proxy or tor:
        return dict(verdict=POSITIVE, **flags)
    if None in (vpn, proxy, tor) or hosting:
        return dict(verdict=UNKNOWN, **flags)
    return dict(verdict=NEGATIVE, **flags)


def _one_flag(positive, hosting=None):
    """Services that answer one yes/no for VPN, proxy and Tor together."""
    if positive is None:
        return None
    return verdict(vpn=positive, proxy=positive, tor=positive, hosting=hosting)


class Limited(Exception):
    """The service says its quota is used up (in a 200 answer)."""


def parse_proxycheck(body, ip):
    r = json.loads(body)
    if r.get('status') in ('denied', 'error') and 'limit' in str(r.get('message', '')).lower():
        raise Limited(r.get('message'))
    entry = r.get(ip) or next((v for k, v in r.items() if isinstance(v, dict) and 'proxy' in v), None)
    if not entry or 'proxy' not in entry:
        return None
    kind = str(entry.get('type', '')).upper()
    listed = entry['proxy'] == 'yes'
    # A hosting allocation alone is review evidence (unknown), as in the plugins.
    return verdict(vpn=listed and kind == 'VPN', proxy=listed and kind not in ('VPN', 'TOR'), tor=listed and kind == 'TOR',
                   hosting=kind == 'HOSTING')


def parse_zowi(body, ip):
    s = json.loads(body).get('security') or {}
    if not s:
        return None
    return verdict(vpn=_flag(s.get('vpn')), proxy=_flag(s.get('proxy')), tor=_flag(s.get('tor')), hosting=_flag(s.get('hosting')))


def parse_ipquery(body, ip):
    r = json.loads(body).get('risk') or {}
    if not r:
        return None
    return verdict(vpn=_flag(r.get('is_vpn')), proxy=_flag(r.get('is_proxy')), tor=_flag(r.get('is_tor')), hosting=_flag(r.get('is_datacenter')))


def parse_ipapi(body, ip):
    r = json.loads(body)
    if r.get('status') != 'success':
        return None
    # One flag for VPN, proxy and Tor; `hosting` is separate.
    return _one_flag(bool(r['proxy']), bool(r.get('hosting')))


def parse_letter(yes, no):
    def parse(body, ip):
        text = body.decode('utf-8', 'replace').strip().upper()
        return _one_flag({yes: True, no: False}.get(text))
    return parse


def parse_iprisk(body, ip):
    r = json.loads(body)
    if 'vpn' not in r:
        return None
    return verdict(vpn=_flag(r.get('vpn')), proxy=_flag(r.get('open_proxy')), tor=_flag(r.get('tor')) or False, hosting=_flag(r.get('data_center')))


def parse_funkemunky(body, ip):
    r = json.loads(body)
    return _one_flag(bool(r['proxy'])) if r.get('success') and 'proxy' in r else None


def parse_freeipapi(body, ip):
    r = json.loads(body)
    return _one_flag(bool(r['isProxy'])) if 'isProxy' in r else None


def parse_negativity(body, ip):
    r = json.loads(body)
    if 'vpn' not in r and 'proxy' not in r:
        return None
    return verdict(vpn=_flag(r.get('vpn')), proxy=_flag(r.get('proxy')), tor=_flag(r.get('tor')) or False, hosting=_flag(r.get('hosting')))


def parse_iplocate(body, ip):
    p = json.loads(body).get('privacy')
    if not p:
        return None
    return verdict(vpn=_flag(p.get('is_vpn')), proxy=_flag(p.get('is_proxy')), tor=_flag(p.get('is_tor')), hosting=_flag(p.get('is_hosting')))


def parse_ip2location(body, ip):
    r = json.loads(body)
    if 'is_proxy' not in r:
        return None
    # The keyless and free plans detect open proxies only; a VPN reads as is_proxy false (ip2location.io/pricing).
    return _one_flag(bool(r['is_proxy']))


def parse_ipapi_is(body, ip):
    r = json.loads(body)
    if 'is_vpn' not in r:
        return None
    return verdict(vpn=_flag(r.get('is_vpn')), proxy=_flag(r.get('is_proxy')), tor=_flag(r.get('is_tor')), hosting=_flag(r.get('is_datacenter')))


def parse_vpnapi(body, ip):
    s = json.loads(body).get('security')
    if not s:
        return None
    return verdict(vpn=_flag(s.get('vpn')) or _flag(s.get('relay')), proxy=_flag(s.get('proxy')), tor=_flag(s.get('tor')))


def parse_iphub(body, ip):
    block = json.loads(body).get('block')
    # 1 = non-residential (hosting, VPN, proxy), 0 = residential, 2 = unsure.
    if block not in (0, 1, 2):
        return None
    return _one_flag(True) if block == 1 else _one_flag(False) if block == 0 else verdict()


class Service:
    def __init__(self, id, name, url, parse, interval=1.0, daily=None, keyed_daily=None, key_env=None, key_required=False,
                 headers=None, terms='not checked', plugin=False, local=False, own=False):
        self.id, self.name, self.url, self.parse, self.interval = id, name, url, parse, interval
        self.keyless_daily, self.keyed_daily = daily, keyed_daily
        self.key_env, self.key_required, self.headers, self.terms, self.plugin = key_env, key_required, headers, terms, plugin
        # local: downloadable lists checked on the server, no lookup. own: built by this benchmark's author.
        self.local, self.own = local, own

    def key(self):
        if not self.key_env:
            return ''
        if self.id == 'proxycheck' and os.environ.get('BENCH_PROVIDERS_PROXYCHECK_KEY') != '1':
            return ''  # the shared key's daily quota belongs to the nightly detection chunks unless released
        return os.environ.get(self.key_env, '')

    @property
    def daily(self):
        """Lookups per day this run may make: the keyed quota when a key is set, else the keyless one."""
        return self.keyed_daily if self.key() else self.keyless_daily

    def available(self):
        return not self.key_required or bool(self.key())


# Terms as checked on 7 October 2026 (source in the note). `plugin`: supported by Connection Guard 0.6.
SERVICES = [
    Service('proxycheck', 'ProxyCheck', lambda ip, k: f'https://proxycheck.io/v2/{q(ip)}?vpn=1' + (f'&key={q(k)}' if k else ''),
            parse_proxycheck, daily=100, keyed_daily=1000, key_env='PROXYCHECK_KEY', plugin=True,
            terms='100 a day keyless, 1,000 with a free key'),
    Service('blackbox', 'Blackbox', lambda ip, k: f'https://blackbox.ipinfo.app/api/v1/{q(ip)}', parse_letter('Y', 'N'), plugin=True,
            terms='keyless; Y also covers hosting and cloud ranges'),
    Service('ipcheck', 'ip-check.net', lambda ip, k: f'https://ip-check.net/api/proxy-detect.php?ip={q(ip)}', parse_letter('TRUE', 'FALSE'),
            plugin=True, terms='no operator, terms or privacy policy published'),
    Service('zowi', 'zowi', lambda ip, k: f'https://api.zowi.gay/{q(ip)}?key=', parse_zowi, plugin=True,
            terms='keyless; operated by the developer of FoxGate'),
    Service('ipquery', 'IPQuery', lambda ip, k: f'https://api.ipquery.io/{q(ip)}?format=json', parse_ipquery, plugin=True,
            terms='keyless, commercial use allowed'),
    Service('ip-api', 'IP-API', lambda ip, k: f'http://ip-api.com/json/{q(ip)}?fields=status,proxy,hosting', parse_ipapi, interval=1.5,
            plugin=True, terms='keyless free use is non-commercial only; HTTP only; 45 a minute'),
    Service('iprisk', 'iprisk.info', lambda ip, k: f'https://api.iprisk.info/v1/{q(ip)}', parse_iprisk,
            terms='keyless; no terms page found'),
    Service('funkemunky', 'funkemunky (KauriVPN)', lambda ip, k: f'https://funkemunky.cc/vpn?ip={q(ip)}', parse_funkemunky,
            terms='keyless; run by the seller of a competing AntiVPN plugin; no terms published'),
    Service('ip2location', 'IP2Location.io', lambda ip, k: f'https://api.ip2location.io/?ip={q(ip)}&format=json' + (f'&key={q(k)}' if k else ''),
            parse_ip2location, daily=1000, keyed_daily=1600, key_env='PROVIDER_KEY_IP2LOCATION',
            terms='1,000 a day keyless, 50,000 a month with a free key; free plans detect open proxies only; attribution required'),
    Service('iplocate', 'IPLocate', lambda ip, k: f'https://iplocate.io/api/lookup/{q(ip)}' + (f'?apikey={q(k)}' if k else ''),
            parse_iplocate, daily=None, keyed_daily=1000, key_env='PROVIDER_KEY_IPLOCATE', terms='1,000 a day with a free key; few keyless answers'),
    Service('ipapi-is', 'ipapi.is', lambda ip, k: f'https://api.ipapi.is/?q={q(ip)}&key={q(k)}', parse_ipapi_is, keyed_daily=1000,
            key_env='PROVIDER_KEY_IPAPI_IS', key_required=True,
            terms='1,000 a day with a free key, commercial use allowed; keyless answers carry no security flags'),
    Service('vpnapi', 'VPNAPI', lambda ip, k: f'https://vpnapi.io/api/{q(ip)}?key={q(k)}', parse_vpnapi, keyed_daily=1000, key_env='VPNAPI_KEY',
            key_required=True, plugin=True, terms='1,000 a day with a free key'),
    Service('iphub', 'IPHub', lambda ip, k: f'https://v2.api.iphub.info/ip/{q(ip)}', parse_iphub, keyed_daily=1000, key_env='PROVIDER_KEY_IPHUB',
            key_required=True, plugin=True, headers=lambda k: {'X-Key': k}, terms='1,000 a day with a free key'),
    Service('freeipapi', 'FreeIPAPI', lambda ip, k: f'https://free.freeipapi.com/api/json/{q(ip)}', parse_freeipapi, interval=1.2,
            terms='keyless; proxy flag only'),
    Service('negativity', 'Negativity', lambda ip, k: f'https://api.negativity.fr/ip/{q(ip)}', parse_negativity, terms='keyless'),
    Service('marvinmc', 'marvinmc.dev', lambda ip, k: f'https://marvinmc.dev/proxy/?ip={q(ip)}', parse_letter('TRUE', 'FALSE'), terms='keyless'),
    Service('cg-intel', 'Connection Guard Intel', None, None, interval=0, plugin=True, local=True, own=True,
            terms='downloadable lists checked on the server (CC BY 4.0); no lookup, no quota; the benchmark author\'s own project'),
    Service('rayzs', 'rayzs.de', lambda ip, k: f'https://www.rayzs.de/provpn/api/proxy.php/?a={q(ip)}', parse_letter('TRUE', 'FALSE'),
            terms='keyless'),
]
BY_ID = {s.id: s for s in SERVICES}


def order(items, seed=20261007):
    """Cohorts interleaved round-robin in a seeded order, so a quota cut leaves every cohort represented."""
    rng = random.Random(seed)
    by_cohort = {}
    for item in items:
        by_cohort.setdefault(item['cohort'], []).append(item)
    for group in by_cohort.values():
        rng.shuffle(group)
    weights = {c: len(g) for c, g in by_cohort.items()}
    out, taken = [], {c: 0 for c in by_cohort}
    total = sum(weights.values())
    while len(out) < total:
        # Next cohort is the one furthest behind its share.
        c = min((c for c in by_cohort if taken[c] < weights[c]), key=lambda c: (taken[c] + 1) / weights[c])
        out.append(by_cohort[c][taken[c]])
        taken[c] += 1
    return out


def query(service, item, key, fetch=None):
    """One lookup. Returns (public record, private raw)."""
    url = service.url(item['ip'], key)
    headers = {'User-Agent': UA, **(service.headers(key) if service.headers else {})}
    started = time.monotonic()
    rec = dict(service=service.id, id=item['id'], cohort=item['cohort'], label=item['label'])
    raw = None
    try:
        if fetch:
            status, body = fetch(url, headers)
        else:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=8) as resp:
                status, body = resp.status, resp.read(65536)
        raw = body[:2000].decode('utf-8', 'replace')
        parsed = service.parse(body, item['ip'])
        if parsed is None:
            rec['error'] = 'unreadable'
        else:
            rec.update(parsed)
    except Limited:
        rec['error'] = 'rate_limited'
    except urllib.error.HTTPError as e:
        rec['error'] = 'rate_limited' if e.code == 429 else f'http_{e.code}'
    except (TimeoutError, OSError) as e:
        rec['error'] = 'timeout' if 'timed out' in str(e) else 'network'
    except ValueError:
        rec['error'] = 'unreadable'
    rec['ms'] = round((time.monotonic() - started) * 1000)
    return rec, raw


def run_service(service, items, sleep=time.sleep, fetch=None):
    key = service.key()
    out, raws, used, limited, streak = [], [], 0, 0, 0
    daily = service.daily
    for item in items:
        if daily is not None and used >= daily:
            out.append(dict(service=service.id, id=item['id'], cohort=item['cohort'], label=item['label'], error='not_queried'))
            continue
        if streak >= 3:
            # Three limits in a row, each after a 60 s pause: the quota is gone for today.
            out.append(dict(service=service.id, id=item['id'], cohort=item['cohort'], label=item['label'], error='rate_limited'))
            continue
        started = time.monotonic()
        rec, raw = query(service, item, key, fetch)
        used += 1
        if rec.get('error') == 'rate_limited':
            limited += 1
            sleep(60 if limited <= 5 else 10)  # back off, then ask again; later limits wait less so a run ends
            rec, raw = query(service, item, key, fetch)
            used += 1
        streak = streak + 1 if rec.get('error') == 'rate_limited' else 0
        out.append(rec)
        raws.append(dict(service=service.id, id=item['id'], body=raw))
        if len(out) % 100 == 0:
            print(f'[providers] {service.id}: {len(out)}/{len(items)} ({limited} rate limits)', flush=True)
        sleep(max(0.0, service.interval * (2 if limited > 3 else 1) - (time.monotonic() - started)))
    return out, raws


def intel_answers(lists, items):
    """Connection Guard Intel read like a service: VPN, Tor or proxy list → positive; relay → negative (a privacy relay
    is not a VPN, and 0.6 lets it in by default); hosting alone → unknown; on no list → unknown, never clean."""
    out = []
    for item in items:
        started = time.monotonic()
        flags = {c: lists.has(c, item['ip']) for c in ('vpn', 'tor', 'proxy', 'relay', 'hosting')}
        rec = dict(service='cg-intel', id=item['id'], cohort=item['cohort'], label=item['label'])
        if flags['vpn'] or flags['tor'] or flags['proxy']:
            rec.update(verdict(vpn=flags['vpn'], proxy=flags['proxy'], tor=flags['tor'], hosting=flags['hosting']))
        elif flags['relay']:
            rec.update(verdict(vpn=False, proxy=False, tor=False, hosting=False), relay=True)
        else:
            rec.update(dict(verdict=UNKNOWN, vpn=None, proxy=None, tor=None, hosting=flags['hosting']))
        rec['ms'] = round((time.monotonic() - started) * 1000, 2)
        out.append(rec)
    return out


def wilson(k, n, z=1.96):
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


def summarize(records, items):
    labels = {i['id']: i['label'] for i in items}
    out = {}
    for service in sorted({r['service'] for r in records}):
        rows = [r for r in records if r['service'] == service]
        answered = [r for r in rows if 'verdict' in r]
        bad = [r for r in rows if labels[r['id']] != 'non_vpn']
        good = [r for r in rows if labels[r['id']] == 'non_vpn']
        caught = sum(r.get('verdict') == POSITIVE for r in bad)
        refused = sum(r.get('verdict') == POSITIVE for r in good)
        cohorts = {}
        for r in rows:
            c = cohorts.setdefault(r['cohort'], dict(n=0, answered=0, positive=0, negative=0, unknown=0, hosting=0))
            c['n'] += 1
            if 'verdict' in r:
                c['answered'] += 1
                c[r['verdict']] += 1
                c['hosting'] += bool(r.get('hosting'))
        ms = [r['ms'] for r in answered]
        errors = {}
        for r in rows:
            if 'error' in r:
                errors[r['error']] = errors.get(r['error'], 0) + 1
        s = BY_ID[service]
        out[service] = dict(
            name=s.name, keyed=bool(s.key()), plugin=s.plugin, terms=s.terms, subjects=len(rows), answered=len(answered),
            caught=caught, bad=len(bad), caught_ci=wilson(caught, len(bad)),
            refused=refused, good=len(good), refused_ci=wilson(refused, len(good)),
            ms_p50=round(statistics.median(ms), 1 if s.local else None) if ms else None,
            ms_p95=round(sorted(ms)[max(0, math.ceil(len(ms) * 0.95) - 1)], 1 if s.local else None) if ms else None,
            local=s.local, own=s.own,
            errors=errors, cohorts=cohorts)
        out[service].update(score=score(out[service]), score_range=score_range(out[service]))
    return out


class Lists:
    """Connection Guard Intel's published lists, checked locally first in the 0.6 chain."""
    def __init__(self, texts):
        self.index = {}
        for category, text in texts.items():
            by_len = {}
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                n = ipaddress.ip_network(line, strict=False)
                by_len.setdefault((n.version, n.prefixlen), set()).add(int(n.network_address))
            self.index[category] = by_len

    def has(self, category, ip):
        a = ipaddress.ip_address(ip)
        bits = 32 if a.version == 4 else 128
        value = int(a)
        return any(value >> (bits - length) << (bits - length) in starts
                   for (version, length), starts in self.index.get(category, {}).items() if version == a.version)

    @classmethod
    def fetch(cls):
        texts = {}
        for category in ('vpn', 'tor', 'relay', 'hosting', 'proxy'):
            req = urllib.request.Request(INTEL + category + '.txt', headers={'User-Agent': UA})
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    texts[category] = resp.read().decode()
            except urllib.error.HTTPError:
                if category != 'proxy':  # proxy.txt is optional (published since 7 Oct 2026, read by 0.6.1)
                    raise
        req = urllib.request.Request(INTEL + 'manifest.json', headers={'User-Agent': UA})
        with urllib.request.urlopen(req, timeout=30) as resp:
            manifest = json.loads(resp.read())
        return cls(texts), dict(as_of=manifest.get('as_of'), sha256={k: v.get('sha256') for k, v in manifest.get('lists', {}).items()})


def simulate(chain, answers, items, lists=None, confirm_blackbox=False, exhausted=()):
    """Replays one lookup chain. The first `positive` or `negative` decides; `unknown`, errors and services listed in
    `exhausted` (no quota left) pass to the next. `intel` checks the local lists (VPN and Tor decide, hosting is
    evidence only). With `confirm_blackbox`, a Blackbox `positive` counts only inside Intel's hosting ranges and is
    otherwise `unknown`. A relay hit (iCloud Private Relay, WARP) lets the player in, as Connection Guard 0.6 does with
    its default `relay: ALLOW`. No decision means the player is let in."""
    decisions = {}
    for item in items:
        decided, by = False, None
        for step in chain:
            if step == 'intel-proxy':
                # Connection Guard 0.6.1 reads Intel's proxy list; 0.6.0 does not.
                if lists and lists.has('proxy', item['ip']):
                    decided, by = True, 'intel-proxy'
                    break
                continue
            if step == 'intel':
                if lists and (lists.has('vpn', item['ip']) or lists.has('tor', item['ip'])):
                    decided, by = True, 'intel'
                    break
                if lists and lists.has('relay', item['ip']):
                    decided, by = False, 'intel-relay'
                    break
                continue
            if step in exhausted:
                continue
            a = answers.get((step, item['id']))
            v = a.get('verdict') if a else None
            if v == POSITIVE and step == 'blackbox' and confirm_blackbox and not (lists and lists.has('hosting', item['ip'])):
                v = UNKNOWN
            if v in (POSITIVE, NEGATIVE):
                decided, by = v == POSITIVE, step
                break
        decisions[item['id']] = (decided, by)
    return decisions


def chain_report(name, chain, decisions, items, **options):
    bad = [i for i in items if i['label'] != 'non_vpn']
    good = [i for i in items if i['label'] == 'non_vpn']
    caught = sum(decisions[i['id']][0] for i in bad)
    refused = sum(decisions[i['id']][0] for i in good)
    cohorts = {}
    for i in items:
        c = cohorts.setdefault(i['cohort'], dict(n=0, blocked=0))
        c['n'] += 1
        c['blocked'] += decisions[i['id']][0]
    by = {}
    for blocked, step in decisions.values():
        if blocked:
            by[step] = by.get(step, 0) + 1
    return dict(name=name, chain=chain, **options, caught=caught, bad=len(bad), refused=refused, good=len(good),
                caught_ci=wilson(caught, len(bad)), refused_ci=wilson(refused, len(good)), cohorts=cohorts, blocked_by=by)


# Connection Guard 0.6.0's shipped order (config.yml provider.order, ip-check.net off by default).
CG_DEFAULT = ['intel', 'proxycheck', 'blackbox', 'zowi', 'ipquery', 'ip-api']
# The 0.6.1 plan (delivery handoff of 7 Oct 2026): Intel's proxy list, Blackbox needs confirmation, IP-API off.
CG_061_PLAN = ['intel', 'intel-proxy', 'proxycheck', 'blackbox', 'zowi', 'ipquery']


def chains(answers, items, lists, services):
    """The shipped chain, Blackbox confirmation, and every keyless service in place of IP-API."""
    limited = tuple(s for s in services if BY_ID[s].daily and BY_ID[s].daily < len(items) and not BY_ID[s].key())
    out = []
    for confirm in (False, True):
        for exhausted, quota in ((limited, 'used up'), ((), 'fresh')):
            base = dict(confirm_blackbox=confirm, quota=quota)
            out.append(chain_report('Connection Guard 0.6 default', CG_DEFAULT,
                                    simulate(CG_DEFAULT, answers, items, lists, confirm, exhausted), items, **base))
            if confirm:
                out.append(chain_report('Connection Guard 0.6.1 plan', CG_061_PLAN,
                                        simulate(CG_061_PLAN, answers, items, lists, confirm, exhausted), items, **base))
            without = [s for s in CG_DEFAULT if s != 'ip-api']
            out.append(chain_report('without IP-API', without, simulate(without, answers, items, lists, confirm, exhausted), items, **base))
            # Blackbox later: behind zowi, or last, where it is asked only when the others have no answer.
            for name, chain in (('Blackbox behind zowi, no IP-API', ['intel', 'proxycheck', 'zowi', 'blackbox', 'ipquery']),
                                ('Blackbox last, no IP-API', ['intel', 'proxycheck', 'zowi', 'ipquery', 'blackbox'])):
                if all(s == 'intel' or s in services for s in chain):
                    out.append(chain_report(name, chain, simulate(chain, answers, items, lists, confirm, exhausted), items, **base))
            for s in services:
                if s in CG_DEFAULT or BY_ID[s].key_required or BY_ID[s].local:
                    continue
                chain = without + [s]
                out.append(chain_report(f'{BY_ID[s].name} instead of IP-API', chain,
                                        simulate(chain, answers, items, lists, confirm, exhausted), items, **base))
                # Also as the confirmation for Blackbox: directly after it.
                at = without.index('blackbox') + 1
                chain = without[:at] + [s] + without[at:]
                out.append(chain_report(f'{BY_ID[s].name} after Blackbox, no IP-API', chain,
                                        simulate(chain, answers, items, lists, confirm, exhausted), items, **base))
    return out


def markdown(summary, chain_rows, meta):
    pct = lambda k, n: f'{k}/{n} ({100 * k / n:.0f} %)' if n else '–'
    lines = [f'# Detection services on their own ({meta["subjects"]} addresses, {meta["started"][:10]})', '',
             'Each service gets every address directly, at its own rate limit and daily quota. `caught` counts VPN, Tor and',
             'proxy addresses answered positive; `refused` counts home and mobile addresses answered positive. Hosting alone',
             'is not a positive. Addresses a service did not answer (quota, errors) count as not caught and not refused.', '',
             f'`Score` = 100 × (share caught − {REFUSAL_WEIGHT} × share refused) − {SPEED_POINTS_PER_S} points per second of median time '
             f'(at most {SPEED_POINTS_MAX}), at least 0; sorted by it. The range is the 95 % interval from both shares: services whose',
             'ranges overlap are not clearly apart.', '',
             '| Service | Score | Key | Answered | Caught | Refused | p50 | p95 | Errors | Terms |', '|---|---|---|---|---|---|---|---|---|---|']
    for sid, s in sorted(summary.items(), key=lambda x: -score(x[1])):
        errs = ', '.join(f'{k} {v}' for k, v in sorted(s['errors'].items())) or '–'
        ms = lambda v: '–' if v is None else f'{v} ms'
        low, high = score_range(s)
        lines.append(f'| {s["name"]}{" ¹" if s["plugin"] else ""}{" ²" if s.get("own") else ""} | {score(s)} ({low}–{high}) | {"yes" if s["keyed"] else "no"} | {s["answered"]}/{s["subjects"]} | '
                     f'{pct(s["caught"], s["bad"])} | {pct(s["refused"], s["good"])} | {ms(s["ms_p50"])} | {ms(s["ms_p95"])} | {errs} | {s["terms"]} |')
    lines += ['', '¹ supported by Connection Guard 0.6.',
              '² built by this benchmark\'s author. Its VPN and Tor lists come from the same operator lists and Tor list that label the',
              'VPN and Tor addresses, so those rows show coverage, not how well it finds unknown servers. Its proxy list uses none of the',
              'three lists the proxy cohort was built from. "Answered" counts every address, listed or not; an unlisted address is unknown.',
              '', '## Chains',
              '', f'Replayed from the answers above. `intel` = Connection Guard Intel lists as of {meta.get("intel", {}).get("as_of")}.',
              '`quota used up`: services with a daily quota below the dataset size answer nothing, as on a busy server.', '',
              '| Chain | Blackbox confirmed | Quota | Caught | Refused |', '|---|---|---|---|---|']
    for c in chain_rows:
        lines.append(f'| {c["name"]} | {"yes" if c["confirm_blackbox"] else "no"} | {c["quota"]} | {pct(c["caught"], c["bad"])} | {pct(c["refused"], c["good"])} |')
    return '\n'.join(lines) + '\n'


def run(recorder, service_ids=None, limit=0):
    items = [json.loads(line) for line in open(scenarios.PRIVATE)]
    items = order(items)
    if limit:
        items = items[:limit]
    wanted = [BY_ID[s] for s in (service_ids or [s.id for s in SERVICES])]
    try:
        lists, intel = Lists.fetch()
    except Exception as e:  # the chains then run without the local lists, and say so; Intel is not measured
        lists, intel = None, dict(error=f'{type(e).__name__}: {e}'[:200])
    local = [s for s in wanted if s.local and lists]
    services = [s for s in wanted if s.available() and not s.local]
    skipped = [s.id for s in wanted if not s.available()]
    print(f'[providers] {len(items)} addresses, services: {", ".join(s.id for s in services)}; no key: {", ".join(skipped) or "none"}', flush=True)
    started = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    with cf.ThreadPoolExecutor(max(1, len(services))) as pool:
        results = list(pool.map(lambda s: run_service(s, items), services))
    records = [r for rec, _ in results for r in rec]
    raws = [r for _, raw in results for r in raw]
    if local:
        records += intel_answers(lists, items)
    answers = {(r['service'], r['id']): r for r in records}
    ids = [s.id for s in services] + [s.id for s in local]
    summary = summarize(records, items)
    chain_rows = chains(answers, items, lists, ids)
    meta = dict(started=started, subjects=len(items), services=ids, skipped_no_key=skipped, intel=intel,
                order_seed=20261007, keys=[s.id for s in services if s.key()])
    private = os.path.join(recorder.private, 'providers')
    os.makedirs(private, exist_ok=True)
    with open(os.path.join(private, 'raw.jsonl'), 'w') as handle:
        for r in raws:
            handle.write(json.dumps(r) + '\n')
    public = os.path.join(recorder.public, 'providers')
    os.makedirs(public, exist_ok=True)
    with open(os.path.join(public, 'answers.jsonl'), 'w') as handle:
        for r in records:
            handle.write(recorder.redact(json.dumps(r)) + '\n')
    recorder.save('providers', 'summary', dict(meta=meta, services=summary, chains=chain_rows))
    open(os.path.join(public, 'report.md'), 'w').write(recorder.redact(markdown(summary, chain_rows, meta)))
    print(f'[providers] done: {len(records)} answers', flush=True)
