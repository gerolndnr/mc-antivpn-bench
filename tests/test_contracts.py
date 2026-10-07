"""Offline contracts: protocol encoding, interposer fairness rules, dataset privacy.

These run without Docker, servers or network (CI job `contracts`).
"""
import asyncio
import hashlib
import ipaddress
import json
import os
import struct
import tempfile
import unittest
import urllib.error

from bench import dataset, engine, interposer, mcclient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PUBLIC = os.path.join(ROOT, 'datasets', 'detection-v1', 'dataset.public.jsonl')
MANIFEST = os.path.join(ROOT, 'datasets', 'detection-v1', 'manifest.json')


class Protocol(unittest.TestCase):
    def test_varint_round_trip(self):
        for value in (0, 1, 127, 128, 255, 25565, 2097151, 2147483647):
            self.assertEqual(mcclient.read_varint_bytes(mcclient.varint(value))[0], value)

    def test_negative_varint_is_five_bytes(self):
        self.assertEqual(len(mcclient.varint(-1)), 5)

    def test_proxy_v2_ipv4_header(self):
        header = mcclient.proxy_v2_header('203.0.113.9', 40000, 25600)
        self.assertTrue(header.startswith(b'\r\n\r\n\x00\r\nQUIT\n'))
        self.assertEqual(header[12], 0x21)          # v2, PROXY command
        self.assertEqual(header[13], 0x11)          # TCP over IPv4
        length = struct.unpack('>H', header[14:16])[0]
        self.assertEqual(length, 12)
        self.assertEqual(header[16:20], ipaddress.ip_address('203.0.113.9').packed)

    def test_proxy_v2_ipv6_header(self):
        header = mcclient.proxy_v2_header('2001:db8::5', 40000, 25600)
        self.assertEqual(header[13], 0x21)
        self.assertEqual(struct.unpack('>H', header[14:16])[0], 36)

    def test_offline_uuid_matches_vanilla(self):
        # Vanilla: UUID.nameUUIDFromBytes("OfflinePlayer:Notch") = b50ad385-829d-3141-a216-7e7d7539ba7f
        self.assertEqual(str(mcclient.offline_uuid('Notch')), 'b50ad385-829d-3141-a216-7e7d7539ba7f')

    def test_text_of_component(self):
        raw = json.dumps({'text': 'Blocked: ', 'extra': [{'text': 'VPN'}]})
        self.assertEqual(mcclient.text_of(raw), 'Blocked: VPN')


class Interposer(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.proxy = interposer.Interposer(self.tmp.name, dict(
            proxycheck=dict(canary='111111-222222-333333-444444', value='REALKEY-000', hosts=['proxycheck.io'])))

    def tearDown(self):
        self.proxy.events.close()
        self.proxy.store.db.close()
        self.tmp.cleanup()

    def request(self, target, headers=(), body=b''):
        return interposer.Request('GET', target, 'HTTP/1.1', list(headers), body)

    def test_canary_and_real_key_share_one_cache_key(self):
        canary = self.proxy.canonical('https', 'proxycheck.io', self.request('/v2/1.2.3.4?key=111111-222222-333333-444444'))
        real = self.proxy.canonical('https', 'proxycheck.io', self.request('/v2/1.2.3.4?key=REALKEY-000'))
        self.assertEqual(canary[0], real[0])
        self.assertNotIn('REALKEY', canary[0])
        self.assertNotIn('111111-222222', canary[0])

    def test_template_key_abstracts_subject(self):
        a = self.proxy.canonical('http', 'ip-api.com', self.request('/json/1.2.3.4?fields=proxy'))
        b = self.proxy.canonical('http', 'ip-api.com', self.request('/json/5.6.7.8?fields=proxy'))
        self.assertNotEqual(a[0], b[0])
        self.assertEqual(a[1], b[1])
        self.assertEqual(a[2], '1.2.3.4')

    def test_ipv6_subject_detected_in_path(self):
        key = self.proxy.canonical('https', 'x.test', self.request('/check/2001:db8::7'))
        self.assertEqual(key[2], '2001:db8::7')

    def test_real_key_only_injected_for_owner_host(self):
        raw = '/v2/1.2.3.4?key=111111-222222-333333-444444'
        self.assertIn('REALKEY-000', self.proxy.inject('proxycheck.io', raw))
        self.assertNotIn('REALKEY-000', self.proxy.inject('evil.example', raw))

    def test_leak_detection_reports_foreign_host(self):
        self.assertEqual(self.proxy.canaries_in('?k=111111-222222-333333-444444'), ['proxycheck'])
        self.assertFalse(self.proxy.secret_allowed('proxycheck', 'evil.example'))

    def test_redaction_removes_real_key(self):
        self.assertNotIn('REALKEY-000', self.proxy.redact('url?key=REALKEY-000'))

    def test_quota_normalisation_only_when_missing(self):
        rule = dict(add_query_if_missing=dict(key='proxycheck'))
        keyless = self.proxy.upstream_request('proxycheck.io', self.request('/v2/1.2.3.4?vpn=1'), rule)
        self.assertIn(b'key=REALKEY-000', keyless)
        keyed = self.proxy.upstream_request('proxycheck.io',
                                            self.request('/v2/1.2.3.4?vpn=1&key=111111-222222-333333-444444'), rule)
        self.assertEqual(keyed.count(b'key='), 1)

    def test_conditional_headers_never_reach_upstream(self):
        request = self.request('/list.txt', headers=[('If-None-Match', '"abc"'), ('If-Modified-Since', 'x')])
        raw = self.proxy.upstream_request('raw.githubusercontent.com', request)
        self.assertNotIn(b'If-None-Match', raw)
        self.assertNotIn(b'If-Modified-Since', raw)

    def test_emulated_quota_limits_per_window(self):
        rule = dict(name='q', quota=dict(limit=2, window_s=60))
        self.assertEqual([self.proxy.over_quota(rule, 'ip-api.com') for _ in range(3)], [False, False, True])
        self.assertFalse(self.proxy.over_quota(rule, 'other.host'))

    def test_rules_first_match_wins(self):
        self.proxy.configure(dict(default='record', rules=[dict(name='a', hosts=['*.bstats.org'], action='deny')]))
        self.assertEqual(self.proxy.rule_for('x.bstats.org')['action'], 'deny')
        self.assertEqual(self.proxy.rule_for('proxycheck.io')['action'], 'record')

    def test_store_round_trip(self):
        answer = dict(status=200, reason='OK', headers=[('Content-Type', 'application/json')], body=b'{}',
                      upstream_ms=12.0)
        self.proxy.store.put('k', 't', 'h', answer, '1.2.3.4')
        self.assertEqual(self.proxy.store.get('k')['body'], b'{}')
        self.assertEqual(self.proxy.store.template('t', '1.2.3.4')['status'], 200)

    def test_single_flight_records_once(self):
        calls = []

        async def fake_forward(*_args, **_kwargs):
            calls.append(1)
            await asyncio.sleep(0.05)
            return dict(status=200, reason='OK', headers=[], body=b'{"proxy":"no"}', upstream_ms=50.0)
        self.proxy.forward = fake_forward
        self.proxy.configure(dict(default='record', rules=[], replay_latency='none'))
        request = self.request('/v2/9.9.9.9')

        async def run():
            contexts = [self.proxy.prepare(request, 'https', 'proxycheck.io', 443, 'c') for _ in range(5)]
            return await asyncio.gather(*[self.proxy.decide(ctx, request, 'https', 443) for ctx in contexts])
        answers = asyncio.run(run())
        self.assertEqual(len(calls), 1)
        self.assertTrue(all(a[0]['body'] == b'{"proxy":"no"}' for a in answers))


class Fairness(unittest.TestCase):
    def test_fallback_services_get_their_own_template_reference(self):
        from bench import heavy
        adapter = dict(lookup_hosts=['proxycheck.io', 'api.ipquery.io', 'ip-api.com'])
        rules = heavy.template_rules(adapter, '192.0.2.1', {'api.ipquery.io': '192.0.2.2'})['rules']
        by_name = {r['name']: r for r in rules}
        self.assertEqual(by_name['template-api.ipquery.io']['reference_ip'], '192.0.2.2')
        self.assertEqual(by_name['template-proxycheck.io']['reference_ip'], '192.0.2.1')
        # Published free-tier quotas still apply to their host.
        self.assertIn('quota', by_name['template-ip-api.com'])
        self.assertNotIn('quota', by_name['template-api.ipquery.io'])

    def test_measurement_rules_block_telemetry_and_updates_for_everyone(self):
        rules = engine.measurement_rules()
        hosts = {h for rule in rules['rules'] if rule['action'] == 'deny' for h in rule['hosts']}
        for host in ('bstats.org', 'sentry.io', 'api.connectionguard.net', 'api.github.com', 'hub.spigotmc.org'):
            self.assertIn(host, hosts)

    def test_profiles_resolve_for_every_product(self):
        for product in ('connection-guard', 'foxgate', 'proxyshield', 'vpnguard'):
            adapter = json.load(open(os.path.join(ROOT, 'products', product + '.json')))
            for profile in ('shipped', 'enforce', 'proxycheck_key', 'free_keys'):
                engine.profile_edits(adapter, profile)
            self.assertEqual(set(adapter['pins']), {'paper', 'folia', 'velocity', 'bungee'})

    def test_every_product_gets_the_same_free_keys(self):
        for product in ('connection-guard', 'foxgate', 'proxyshield', 'vpnguard'):
            adapter = json.load(open(os.path.join(ROOT, 'products', product + '.json')))
            values = json.dumps(engine.profile_edits(adapter, 'free_keys'))
            self.assertIn('{canary:proxycheck}', values)
            self.assertIn('{canary:vpnapi}', values)

    def test_canaries_are_format_compatible(self):
        canaries = engine.make_canaries(seed=1)
        self.assertRegex(canaries['proxycheck'], r'^\d{6}-\d{6}-\d{6}-\d{6}$')
        self.assertRegex(canaries['vpnapi'], r'^[0-9a-f]{32}$')


class Dataset(unittest.TestCase):
    def setUp(self):
        self.items = [json.loads(line) for line in open(PUBLIC)]

    def test_no_volunteer_address_is_published(self):
        for item in self.items:
            if item['source'] == 'ripe-atlas':
                self.assertNotIn('ip', item)
                self.assertIn('probe_id', item['rebuild'])

    def test_counts_match_manifest(self):
        manifest = json.load(open(MANIFEST))
        counts = {}
        for item in self.items:
            counts[item['cohort']] = counts.get(item['cohort'], 0) + 1
        self.assertEqual(counts, manifest['counts'])

    def test_every_item_has_provenance(self):
        manifest = json.load(open(MANIFEST))
        for item in self.items:
            self.assertIn(item['label'], ('vpn', 'tor', 'proxy', 'non_vpn'))
            self.assertTrue(item['source'])
        for name, source in manifest['sources'].items():
            self.assertRegex(source['sha256'], r'^[0-9a-f]{64}$', name)

    def test_ids_unique_and_no_duplicate_addresses(self):
        ids = [i['id'] for i in self.items]
        self.assertEqual(len(ids), len(set(ids)))
        published = [i['ip'] for i in self.items if 'ip' in i]
        self.assertEqual(len(published), len(set(published)))

    def test_labels_never_come_from_detection_providers(self):
        allowed = {'mullvad', 'nordvpn', 'pia', 'ivpn', 'surfshark', 'torproject-bulk-exit-list',
                   'checked-public-proxy-lists', 'ripe-atlas'}
        self.assertTrue({i['source'] for i in self.items} <= allowed)

    def test_spread_is_deterministic(self):
        candidates = [dict(ip=f'198.51.{i}.{j}', country=str(i % 5)) for i in range(20) for j in range(1, 4)]
        a = dataset.spread(candidates, 10, __import__('random').Random(7))
        b = dataset.spread(candidates, 10, __import__('random').Random(7))
        self.assertEqual([x['ip'] for x in a], [x['ip'] for x in b])
        self.assertEqual(len({dataset.slash24(x['ip']) for x in a}), 10)


if __name__ == '__main__':
    unittest.main()


class Analysis(unittest.TestCase):
    def test_wilson_interval(self):
        from bench import report
        low, high = report.wilson(45, 50)
        self.assertAlmostEqual(low, 0.786, places=2)
        self.assertAlmostEqual(high, 0.957, places=2)
        self.assertEqual(report.wilson(0, 0), (None, None))

    def test_error_attribution_stays_inside_one_entry(self):
        adapter = dict(data_dir={'paper': 'ConnectionGuard'}, id='connection-guard', name='Connection Guard')
        console = '\n'.join([
            '[12:00:00 ERROR]: [PaperVersionFetcher] Error while parsing version list',
            'java.net.SocketException: Unexpected end of file',
            '\tat java.base/sun.net.www.http.HttpClient.parseHTTP(HttpClient.java:735)',
            '[12:00:01 INFO]: [ConnectionGuard] Enabling ConnectionGuard v0.5.0',
            '[12:00:02 ERROR]: Error occurred while enabling ConnectionGuard v0.5.0',
            '\tat com.github.gerolndnr.connectionguard.spigot.Plugin.onEnable(Plugin.java:1)',
            '[12:00:03 ERROR]: [OtherPlugin] broke',
        ])
        console += '\n[12:00:04 ERROR]: Failed to request yggdrasil public key\n\tat sun.net.www.protocol.http.HttpURLConnection.getInputStream(X.java:1)'
        hits = engine.product_errors(console, adapter, 'paper')
        self.assertEqual(len(hits), 1)
        self.assertIn('enabling ConnectionGuard', hits[0])

    def test_list_parser_accepts_common_formats(self):
        from bench import heavy
        nets = heavy.parse_list(b'# comment\n1.2.3.4\n5.6.7.0/24\nsocks5://9.9.9.9:1080\n10.0.0.1:8080\n2001:db8::/32\nbad\n')
        self.assertEqual([str(n) for n in nets], ['1.2.3.4/32', '5.6.7.0/24', '9.9.9.9/32', '10.0.0.1/32',
                                                  '2001:db8::/32'])


class Publication(unittest.TestCase):
    def test_public_logs_mask_addresses_but_not_timestamps(self):
        from bench.__main__ import Recorder
        recorder = Recorder.__new__(Recorder)
        recorder.subject_map, recorder._sorted = {'203.0.113.5': '<tor-0001>'}, ['203.0.113.5']
        text = recorder.redact('[14:29:23 INFO] 203.0.113.5 joined; 95.43.29.52:1 /[2a02:6ea0::7]:2 127.0.0.1 1.21.11')
        self.assertEqual(text, '[14:29:23 INFO] <tor-0001> joined; <ip>:1 /[<ip6>]:2 127.0.0.1 1.21.11')

    def test_java_ipv6_spelling_maps_to_subject_id(self):
        from bench.__main__ import address_forms
        self.assertIn('2a02:6ea0:2901:0:0:0:0:7', address_forms('2a02:6ea0:2901::7'))

    def test_synthetic_subjects_avoid_volunteer_networks(self):
        from bench import heavy
        items = [dict(cohort='residential', ip=f'84.{i}.10.20') for i in range(20)]
        own = {dataset.slash24(i['ip']) for i in items}
        for subject in heavy.synthetic_subjects(items, 200, 1):
            self.assertNotIn(dataset.slash24(subject['ip']), own)


class Providers(unittest.TestCase):
    """Family `providers`: answer parsing, quota handling and chain replay, without network."""

    def setUp(self):
        from bench import providers
        self.p = providers

    def test_verdicts_follow_the_plugins_reading(self):
        p = self.p
        self.assertEqual(p.parse_zowi(b'{"security":{"vpn":true,"proxy":false,"tor":false,"hosting":true}}', '')['verdict'], p.POSITIVE)
        # Hosting alone is review evidence: the chain asks the next service.
        self.assertEqual(p.parse_zowi(b'{"security":{"vpn":false,"proxy":false,"tor":false,"hosting":true}}', '')['verdict'], p.UNKNOWN)
        self.assertEqual(p.parse_zowi(b'{"security":{"vpn":false,"proxy":false,"tor":false,"hosting":false}}', '')['verdict'], p.NEGATIVE)
        self.assertIsNone(p.parse_zowi(b'{"error":"limit"}', ''))
        self.assertEqual(p.parse_letter('Y', 'N')(b'Y\n', '')['verdict'], p.POSITIVE)
        self.assertIsNone(p.parse_letter('Y', 'N')(b'<html>', ''))
        self.assertEqual(p.parse_ipapi(b'{"status":"success","proxy":false,"hosting":true}', '')['verdict'], p.UNKNOWN)
        self.assertIsNone(p.parse_ipapi(b'{"status":"fail"}', ''))
        self.assertEqual(p.parse_proxycheck(b'{"status":"ok","192.0.2.1":{"proxy":"yes","type":"VPN"}}', '192.0.2.1')['verdict'], p.POSITIVE)
        self.assertEqual(p.parse_proxycheck(b'{"status":"ok","192.0.2.1":{"proxy":"no","type":"Hosting"}}', '192.0.2.1')['verdict'], p.UNKNOWN)
        self.assertEqual(p.parse_proxycheck(b'{"status":"ok","192.0.2.1":{"proxy":"no","type":"Residential"}}', '192.0.2.1')['verdict'], p.NEGATIVE)
        self.assertEqual(p.parse_ipquery(b'{"risk":{"is_vpn":false,"is_proxy":false,"is_tor":false,"is_datacenter":false}}', '')['verdict'], p.NEGATIVE)
        self.assertEqual(p.parse_iphub(b'{"block":2}', '')['verdict'], p.UNKNOWN)
        self.assertEqual(p.parse_iphub(b'{"block":1}', '')['verdict'], p.POSITIVE)

    def test_interleaved_order_is_stable_and_keeps_cohort_shares(self):
        items = [dict(id=f'{c}-{i}', cohort=c) for c, n in (('a', 60), ('b', 30), ('c', 10)) for i in range(n)]
        first = self.p.order(items)
        self.assertEqual([i['id'] for i in first], [i['id'] for i in self.p.order(items)])
        head = [i['cohort'] for i in first[:20]]
        self.assertEqual((head.count('a'), head.count('b'), head.count('c')), (12, 6, 2))

    def test_daily_quota_leaves_the_rest_not_queried(self):
        p = self.p
        service = p.Service('t', 'T', lambda ip, k: f'https://example.invalid/{ip}', p.parse_letter('Y', 'N'), interval=0, daily=2)
        items = [dict(id=f's{i}', ip=f'192.0.2.{i}', cohort='x', label='vpn') for i in range(4)]
        out, _ = p.run_service(service, items, sleep=lambda s: None, fetch=lambda url, headers: (200, b'Y'))
        self.assertEqual([r.get('verdict', r.get('error')) for r in out], ['positive', 'positive', 'not_queried', 'not_queried'])

    def test_rate_limited_is_retried_once(self):
        p = self.p
        calls = []

        def fetch(url, headers):
            calls.append(url)
            if len(calls) == 1:
                raise urllib.error.HTTPError(url, 429, 'Too Many Requests', {}, None)
            return 200, b'N'
        service = p.Service('t', 'T', lambda ip, k: f'https://example.invalid/{ip}', p.parse_letter('Y', 'N'), interval=0)
        out, _ = p.run_service(service, [dict(id='s', ip='192.0.2.1', cohort='x', label='non_vpn')], sleep=lambda s: None, fetch=fetch)
        self.assertEqual((len(calls), out[0]['verdict']), (2, p.NEGATIVE))

    def test_chain_first_answer_decides_and_blackbox_needs_confirmation(self):
        p = self.p
        lists = p.Lists(dict(vpn='198.51.100.0/24\n', tor='', relay='', hosting='203.0.113.0/24\n'))
        items = [dict(id='home', ip='192.0.2.1', label='non_vpn', cohort='residential'),
                 dict(id='dc', ip='203.0.113.5', label='proxy', cohort='proxy'),
                 dict(id='vpn', ip='198.51.100.9', label='vpn', cohort='commercial_vpn')]
        answers = {('blackbox', 'home'): dict(verdict='positive'), ('blackbox', 'dc'): dict(verdict='positive'),
                   ('zowi', 'home'): dict(verdict='negative'), ('zowi', 'dc'): dict(verdict='negative'),
                   ('proxycheck', 'home'): dict(verdict='negative')}
        chain = ['intel', 'proxycheck', 'blackbox', 'zowi']
        plain = p.simulate(chain, answers, items, lists)
        self.assertEqual(plain, {'home': (False, 'proxycheck'), 'dc': (True, 'blackbox'), 'vpn': (True, 'intel')})
        used_up = p.simulate(chain, answers, items, lists, exhausted=('proxycheck',))
        self.assertEqual(used_up['home'], (True, 'blackbox'))
        confirmed = p.simulate(chain, answers, items, lists, confirm_blackbox=True, exhausted=('proxycheck',))
        # Outside Intel's hosting ranges an unconfirmed Blackbox listing passes on; inside, it still counts.
        self.assertEqual((confirmed['home'], confirmed['dc']), ((False, 'zowi'), (True, 'blackbox')))

    def test_public_answers_carry_no_addresses(self):
        p = self.p
        service = p.Service('t', 'T', lambda ip, k: f'https://example.invalid/{ip}', p.parse_letter('Y', 'N'), interval=0)
        out, raw = p.run_service(service, [dict(id='s', ip='192.0.2.77', cohort='x', label='vpn')], sleep=lambda s: None,
                                 fetch=lambda url, headers: (200, b'Y'))
        self.assertNotIn('192.0.2.77', json.dumps(out))


class Overview(unittest.TestCase):
    """bench.overview: draws from public results only, newest version per plugin, no addresses."""

    def test_run_step_forwards_its_env_into_the_container(self):
        # A variable set on the runner but missing from `docker run -e` never reaches the harness.
        import yaml
        path = os.path.join(os.path.dirname(__file__), '..', '.github', 'workflows', 'bench.yml')
        steps = yaml.safe_load(open(path))['jobs']['bench']['steps']
        run = next(s for s in steps if s.get('name') == 'Run')
        for name in run['env']:
            self.assertIn(f'-e {name}', run['run'], name)

    def test_overview_accent_follows_the_shown_value(self):
        from bench import overview
        self.assertEqual(overview.fmt_ms(2.04), '2.0 ms')
        self.assertEqual(overview.fmt_ms(1.6), '1.6 ms')
        self.assertEqual(overview.fmt_ms(287.0), '287 ms')
        self.assertEqual(overview.best({'a': 2.0, 'b': 1.6, 'c': 1.62}, True, overview.fmt_ms), {'b', 'c'})
        self.assertEqual(overview.best({'a': 2.0, 'b': 1.6}, True, overview.fmt_ms), {'b'})

    def test_overview_from_minimal_results(self):
        from bench import overview
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, 'detection'))
            os.makedirs(os.path.join(tmp, 'failure'))
            rows = []
            for i, (cohort, label) in enumerate([('commercial_vpn', 'vpn'), ('residential', 'non_vpn')]):
                rows.append(dict(subject=f'{cohort}-{i}', cohort=cohort, label=label, attempt=0, products={
                    p: dict(blocked=label == 'vpn', outcome='DENY_LOGIN' if label == 'vpn' else 'ALLOW', decision_ms=10)
                    for p in ('connection-guard', 'connection-guard-candidate', 'foxgate')}))
            json.dump(dict(profile='enforce', platform='velocity', rows=rows), open(os.path.join(tmp, 'detection', 'enforce.json'), 'w'))
            json.dump(dict(product='foxgate', fault='timeout', during=dict(vpn=dict(blocked=True), tor=dict(blocked=True),
                           residential=dict(blocked=False, decision_ms=12000))), open(os.path.join(tmp, 'failure', 'foxgate-timeout.json'), 'w'))
            json.dump(dict(run_id='1-detection', environment=dict(started='2026-10-06T22:25:25+00:00')), open(os.path.join(tmp, 'manifest.json'), 'w'))
            page, height = overview.build([tmp])
            self.assertIn('Detection and false positives', page)
            self.assertIn('When detection services fail', page)
            self.assertIn('FoxGate', page)
            self.assertGreater(height, 600)
            # Only the newest Connection Guard is drawn.
            self.assertEqual(overview.newest_only(['connection-guard-candidate', 'connection-guard', 'foxgate']),
                             ['connection-guard-candidate', 'foxgate'])
            self.assertIsNone(__import__('re').search(r'\b\d{1,3}(\.\d{1,3}){3}\b', page.split('</style>', 1)[1]))

    def test_version_order(self):
        from bench import overview
        self.assertLess(overview.version_key('1.2.0-pre10'), overview.version_key('1.2.0'))
        self.assertLess(overview.version_key('0.5.1'), overview.version_key('0.6.0'))


class ProviderQuota(unittest.TestCase):
    def test_three_limits_in_a_row_end_the_day(self):
        from bench import providers as p
        calls = []

        def fetch(url, headers):
            calls.append(url)
            raise urllib.error.HTTPError(url, 429, 'Too Many Requests', {}, None)
        service = p.Service('t', 'T', lambda ip, k: f'https://example.invalid/{ip}', p.parse_letter('Y', 'N'), interval=0)
        items = [dict(id=f's{i}', ip=f'192.0.2.{i}', cohort='x', label='vpn') for i in range(10)]
        out, _ = p.run_service(service, items, sleep=lambda s: None, fetch=fetch)
        self.assertEqual(len(calls), 6)  # three subjects, each asked twice
        self.assertTrue(all(r['error'] == 'rate_limited' for r in out))

    def test_proxycheck_limit_message_is_a_rate_limit(self):
        from bench import providers as p
        service = p.BY_ID['proxycheck']
        rec, _ = p.query(service, dict(id='s', ip='192.0.2.1', cohort='x', label='vpn'), '',
                         fetch=lambda url, headers: (200, b'{"status":"denied","message":"1,000 free queries exhausted. Daily limit reached."}'))
        self.assertEqual(rec['error'], 'rate_limited')


class UnlistedLookups(unittest.TestCase):
    def test_lookup_to_an_unlisted_host_is_caught(self):
        from bench import heavy
        events = [dict(host='api.zowi.gay', subject_ip='198.51.100.7'), dict(host='blackbox.ipinfo.app', subject_ip='198.51.100.7'),
                  dict(host='central.zowi.gay', subject_ip=None)]
        self.assertEqual(heavy.unlisted_lookups(events, ['blackbox.ipinfo.app', 'central.zowi.gay'], {'198.51.100.7'}), {'api.zowi.gay': 1})

    def test_adapters_list_their_own_lookup_services(self):
        # Hosts each product is known to ask about a player's address (from published egress logs).
        known = {'foxgate': ['api.zowi.gay', 'blackbox.ipinfo.app', 'ip-api.com'],
                 'connection-guard-candidate': ['api.zowi.gay', 'blackbox.ipinfo.app', 'api.ipquery.io', 'proxycheck.io']}
        for product, hosts in known.items():
            adapter = json.load(open(os.path.join(ROOT, 'products', product + '.json')))
            for host in hosts:
                self.assertIn(host, adapter['lookup_hosts'], f'{product}: {host}')


class RelayInChains(unittest.TestCase):
    def test_relay_hit_lets_the_player_in_before_any_service(self):
        from bench import providers as p
        lists = p.Lists(dict(vpn='', tor='', relay='104.28.0.0/16\n', hosting=''))
        items = [dict(id='warp', ip='104.28.200.15', label='non_vpn', cohort='residential')]
        answers = {('blackbox', 'warp'): dict(verdict='positive')}
        self.assertEqual(p.simulate(['intel', 'blackbox'], answers, items, lists), {'warp': (False, 'intel-relay')})


class IntelProxyStep(unittest.TestCase):
    def test_proxy_list_counts_only_in_the_061_step(self):
        from bench import providers as p
        lists = p.Lists(dict(vpn='', tor='', relay='', hosting='', proxy='45.90.28.7\n'))
        items = [dict(id='px', ip='45.90.28.7', label='proxy', cohort='proxy')]
        self.assertEqual(p.simulate(['intel'], {}, items, lists), {'px': (False, None)})
        self.assertEqual(p.simulate(['intel', 'intel-proxy'], {}, items, lists), {'px': (True, 'intel-proxy')})


class IntelAsService(unittest.TestCase):
    def test_intel_reads_like_a_service(self):
        from bench import providers as p
        lists = p.Lists(dict(vpn='45.90.28.0/24\n', tor='', relay='104.28.0.0/16\n', hosting='45.90.29.0/24\n', proxy='45.90.30.7\n'))
        items = [dict(id=i, ip=ip, label='x', cohort='x') for i, ip in
                 (('vpn', '45.90.28.7'), ('proxy', '45.90.30.7'), ('relay', '104.28.200.15'), ('dc', '45.90.29.1'), ('none', '8.8.4.4'))]
        got = {r['id']: r['verdict'] for r in p.intel_answers(lists, items)}
        self.assertEqual(got, dict(vpn='positive', proxy='positive', relay='negative', dc='unknown', none='unknown'))
        summary = p.summarize(p.intel_answers(lists, items), items)
        self.assertTrue(summary['cg-intel']['own'] and summary['cg-intel']['local'])


class BoughtProducts(unittest.TestCase):
    """A paid JAR's buyer id must never reach a public result (bench/private.py)."""

    def setUp(self):
        from bench import private
        self.private = private
        self.directory = tempfile.mkdtemp()
        self.saved = private.DIRECTORY
        private.DIRECTORY = self.directory
        self.jar = b'PK fake jar 7771234'
        with open(os.path.join(self.directory, 'AdvancedAntiVPN-2.31.8.jar'), 'wb') as handle:
            handle.write(self.jar)
        with open(os.path.join(self.directory, 'private.json'), 'w') as handle:
            json.dump(dict(sha256={'AdvancedAntiVPN-2.31.8.jar': hashlib.sha256(self.jar).hexdigest()},
                           redact=['7771234', '55501']), handle)

    def tearDown(self):
        self.private.DIRECTORY = self.saved

    def test_public_repository_holds_no_hash_or_id(self):
        for pin in self.private.pins().values():
            self.assertTrue(pin['private'])
            self.assertFalse({'sha256', 'sha512', 'url', 'redact'} & set(pin))

    def test_jar_is_verified_against_the_private_hash(self):
        self.assertTrue(self.private.jar('advancedantivpn-2.31.8').endswith('AdvancedAntiVPN-2.31.8.jar'))
        with open(os.path.join(self.directory, 'AdvancedAntiVPN-2.31.8.jar'), 'ab') as handle:
            handle.write(b'x')
        with self.assertRaises(RuntimeError):
            self.private.jar('advancedantivpn-2.31.8')

    def test_buyer_id_is_masked_and_a_leak_is_found(self):
        line = 'Plugin registered to 7771234 | 55501 GET /legacy/premium.php?user_id=7771234'
        self.assertNotIn('7771234', self.private.redact(line))
        self.assertNotIn('55501', self.private.redact(line))
        self.assertEqual(self.private.redact('"served_ms": 77712345, "port": 555012'), '"served_ms": 77712345, "port": 555012')
        results = tempfile.mkdtemp()
        with open(os.path.join(results, 'clean.log'), 'w') as handle:
            handle.write(self.private.redact(line))
        self.assertEqual(self.private.leaks(results), [])
        with open(os.path.join(results, 'leak.log'), 'w') as handle:
            handle.write(line)
        self.assertEqual(self.private.leaks(results), ['leak.log'])

    def test_egress_log_masks_the_buyer_id(self):
        spec = engine.secrets_spec(dict(proxycheck='1-2-3-4', vpnapi='ab'))
        box = interposer.Interposer(tempfile.mkdtemp(), interposer.secrets_from_environment(spec))
        self.assertNotIn('7771234', box.redact('/legacy/premium.php?user_id=7771234&resource_id=101081'))


class PinnedVersionsAreNotAddresses(unittest.TestCase):
    def test_four_part_version_survives_masking(self):
        from bench.__main__ import _mask
        self.assertEqual(_mask('1.10.1.1', '<ip>'), '1.10.1.1')
        self.assertEqual(_mask('8.8.4.4', '<ip>'), '<ip>')

    def test_every_adapter_has_an_upgrade_marker_when_it_pins_a_previous_release(self):
        from bench import scenarios
        for name in os.listdir(os.path.join(ROOT, 'products')):
            if name.endswith('-pins.json') or not name.endswith('.json'):
                continue
            adapter = json.load(open(os.path.join(ROOT, 'products', name)))
            if adapter.get('previous_pins'):
                self.assertIn(adapter['id'], scenarios.UPGRADE_MARKERS, name)


class PlayerAccounts(unittest.TestCase):
    def test_name_lookup_answers_like_a_real_account(self):
        box = interposer.Interposer(tempfile.mkdtemp())
        box.configure(engine.measurement_rules())
        self.assertEqual(box.rule_for('api.mojang.com', '/users/profiles/minecraft/kauriv000019')['action'], 'mojang-profile')
        self.assertNotEqual(box.rule_for('api.mojang.com', '/other')['action'], 'mojang-profile')
        answer = json.loads(interposer.Interposer.mojang_profile('/users/profiles/minecraft/kauriv000019')['body'])
        self.assertEqual(answer['name'], 'kauriv000019')
        self.assertEqual(len(answer['id']), 32)
        self.assertEqual(answer['id'][12], '3')  # name-based (offline-mode) UUID


class MeasuredDates(unittest.TestCase):
    def test_span_of_the_runs_shown(self):
        from bench import overview
        m = lambda s, d=0: dict(environment=dict(started=s), duration_s=d)
        self.assertEqual(overview.measured_dates([m('2026-10-06T22:25:11+00:00', 3000), m('2026-10-07T08:26:33+00:00')]),
                         '6–7 October 2026')
        self.assertEqual(overview.measured_dates([m('2026-10-07T08:00:00+00:00', 60)]), '7 October 2026')


class ReadmeOverviewSelection(unittest.TestCase):
    """A newer run with only some products adds them; the other products keep their newest result."""

    def run_folder(self, base, run_id, products, detection_profile=None):
        folder = os.path.join(base, str(run_id))
        os.makedirs(os.path.join(folder, 'platform'))
        json.dump(dict(products=products, environment=dict(started='2026-10-07T08:00:00+00:00')),
                  open(os.path.join(folder, 'manifest.json'), 'w'))
        for p in products:
            json.dump(dict(product=p, platform='paper', result=[]), open(os.path.join(folder, 'platform', f'{p}-paper.json'), 'w'))
        if detection_profile:
            os.makedirs(os.path.join(folder, 'detection'))
            rows = [dict(subject=f's{i}', cohort='tor', label='vpn', attempt=0,
                         products={p: dict(blocked=True) for p in products}) for i in range(3)]
            json.dump(dict(profile=detection_profile, chunk=None, rows=rows),
                      open(os.path.join(folder, 'detection', f'{detection_profile}.json'), 'w'))

    def test_partial_run_adds_products(self):
        from bench import latest
        base = tempfile.mkdtemp()
        self.run_folder(base, 2, ['kaurivpn'], 'enforce')
        self.run_folder(base, 1, ['connection-guard', 'foxgate'], 'enforce')
        saved = latest.runs, latest.dataset_size
        latest.runs = lambda repo, limit: [dict(id=2), dict(id=1)]
        latest.dataset_size = lambda: 3
        try:
            chosen, providers, profile = latest.select('x', base)
        finally:
            latest.runs, latest.dataset_size = saved
        self.assertEqual(sorted(chosen['functional']), ['connection-guard', 'foxgate', 'kaurivpn'])
        self.assertEqual(sorted(chosen['detection']), ['connection-guard', 'foxgate', 'kaurivpn'])
        self.assertEqual(profile, 'enforce')

    def test_keyed_profile_only_once_every_product_has_it(self):
        from bench import latest
        base = tempfile.mkdtemp()
        self.run_folder(base, 3, ['connection-guard', 'foxgate'], 'proxycheck_key')
        self.run_folder(base, 2, ['kaurivpn'], 'enforce')
        self.run_folder(base, 1, ['connection-guard', 'foxgate'], 'enforce')
        saved = latest.runs, latest.dataset_size
        latest.runs = lambda repo, limit: [dict(id=3), dict(id=2), dict(id=1)]
        latest.dataset_size = lambda: 3
        try:
            chosen, _, profile = latest.select('x', base)
        finally:
            latest.runs, latest.dataset_size = saved
        self.assertEqual(profile, 'enforce')
        self.assertEqual(chosen['detection']['connection-guard'][0][0], '1')


class ProviderScore(unittest.TestCase):
    def test_score_weights_refusals_three_times_and_speed_only_a_little(self):
        from bench import providers as p
        s = dict(caught=379, bad=382, refused=12, good=310, ms_p50=69.0, caught_ci=[0.977, 0.997], refused_ci=[0.022, 0.067])
        self.assertEqual(p.score(s), 87.3)
        local = dict(caught=289, bad=382, refused=0, good=310, ms_p50=0.0, caught_ci=[0.71, 0.80], refused_ci=[0.0, 0.012])
        self.assertEqual(p.score(local), 75.7)
        low, high = p.score_range(s)
        self.assertLess(low, p.score(s))
        self.assertGreater(high, p.score(s))
        self.assertEqual(p.score(dict(caught=0, bad=382, refused=0, good=310, ms_p50=612.0)), 0.0)


class OverviewJobNeedsNoPackages(unittest.TestCase):
    """.github/workflows/overview.yml runs bench.latest with bare Python: no yaml, cryptography or h2."""

    def test_latest_and_score_import_without_packages(self):
        import subprocess, sys
        code = ('import builtins, sys\n'
                'real = builtins.__import__\n'
                'def guard(name, *a, **k):\n'
                '    if name.split(".")[0] in ("yaml", "cryptography", "h2"): raise ImportError(name)\n'
                '    return real(name, *a, **k)\n'
                'builtins.__import__ = guard\n'
                'from bench import latest, overview, score\n'
                's = dict(caught=1, bad=2, refused=0, good=2, ms_p50=0)\n'
                'assert score.score(s) == 50.0\n')
        env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, 'harness'))
        result = subprocess.run([sys.executable, '-c', code], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class ServiceDownDuringRun(unittest.TestCase):
    def test_ten_timeouts_in_a_row_stop_the_service(self):
        from bench import providers as p
        calls = []
        def fetch(url, headers):
            calls.append(url)
            raise TimeoutError('timed out')
        service = next(s for s in p.SERVICES if s.id == 'zowi')
        items = [dict(id=f's{i}', ip='45.90.28.7', cohort='tor', label='vpn') for i in range(50)]
        out, _ = p.run_service(service, items, sleep=lambda s: None, fetch=fetch)
        self.assertEqual(len(calls), p.UNAVAILABLE_AFTER)
        self.assertEqual(sum(r.get('error') == 'unavailable' for r in out), 50 - p.UNAVAILABLE_AFTER)
        summary = p.summarize(out, items)
        self.assertTrue(summary['zowi']['unavailable'])

    def test_readme_keeps_the_earlier_result_of_a_service_that_was_down(self):
        from bench import latest, score
        base = tempfile.mkdtemp()
        entry = lambda caught, errors: dict(name='zowi', caught=caught, bad=382, refused=2, good=310, subjects=692,
                                            answered=692 - sum(errors.values()), ms_p50=272, errors=errors,
                                            caught_ci=None, refused_ci=None)
        for run_id, started, zowi in ((2, '2026-10-07T13:00:00+00:00', entry(0, {'timeout': 10, 'unavailable': 682})),
                                      (1, '2026-10-07T09:00:00+00:00', entry(339, {}))):
            folder = os.path.join(base, str(run_id), 'providers')
            os.makedirs(folder)
            json.dump(dict(meta=dict(started=started, subjects=692), services=dict(zowi=zowi), chains=[]),
                      open(os.path.join(folder, 'summary.json'), 'w'))
            json.dump(dict(products=[], environment=dict(started=started)), open(os.path.join(base, str(run_id), 'manifest.json'), 'w'))
        saved = latest.runs
        latest.runs = lambda repo, limit: [dict(id=2), dict(id=1)]
        try:
            chosen, providers, profile = latest.select('x', base)
        finally:
            latest.runs = saved
        dirs = latest.merge(chosen, providers, profile, base)
        merged = json.load(open(os.path.join(dirs['providers'][0], 'providers', 'summary.json')))
        self.assertEqual(merged['services']['zowi']['caught'], 339)
        self.assertEqual(merged['services']['zowi']['from_date'], '2026-10-07')
        self.assertTrue(score.unavailable(entry(0, {'timeout': 10, 'unavailable': 682})))


class AdaptivePacing(unittest.TestCase):
    """bench.heavy.Pacer: a plugin that decides at login moves on fast; one that kicks after the join keeps its window."""

    def run_subjects(self, pacer, outcomes):
        windows = []
        for outcome in outcomes:
            window = pacer.window({})
            windows.append(window)
            marks = dict(joined=100.0, decided=100.0 + 1000 * outcome[1]) if outcome[0] == 'DENY_PLAY' else {}
            pacer.observe(dict(outcome=outcome[0], marks=marks), window)
        return windows

    def test_login_decider_gets_the_short_window_after_calibration(self):
        from bench import heavy
        p = heavy.Pacer()
        windows = self.run_subjects(p, [('ALLOW', 0)] * 40)
        self.assertTrue(all(w == heavy.OBSERVE_S for w in windows[:heavy.CALIBRATION]))
        self.assertEqual(windows[heavy.CALIBRATION], heavy.OBSERVE_MIN_S)
        self.assertEqual(windows[heavy.PROBE_EVERY * 3 - 1], heavy.OBSERVE_S)  # every 10th subject is a full probe

    def test_late_kick_widens_the_window(self):
        from bench import heavy
        p = heavy.Pacer()
        self.run_subjects(p, [('DENY_PLAY', 1.2)] + [('ALLOW', 0)] * 25)
        self.assertAlmostEqual(p.observe_s, 2.4)
        self.run_subjects(p, [('DENY_PLAY', 6.0)])
        self.assertEqual(p.observe_s, heavy.OBSERVE_S)

    def test_interval_backs_off_on_provider_errors_and_recovers(self):
        from bench import heavy
        p = heavy.Pacer()
        p.after(['ip-api.com'])
        self.assertAlmostEqual(p.interval, heavy.INTERVAL_START_S * 1.5)
        for _ in range(20):
            p.after([])
        self.assertAlmostEqual(p.interval, heavy.INTERVAL_START_S * 1.5 / 1.25)

    def test_fixed_mode_keeps_the_old_pacing(self):
        from bench import heavy
        p = heavy.Pacer(fixed=True)
        self.assertTrue(all(w == heavy.OBSERVE_S for w in self.run_subjects(p, [('ALLOW', 0)] * 30)))
        p.after(['x'])
        self.assertEqual(p.interval, heavy.SUBJECT_INTERVAL_S)


class RetryRowsPerProduct(unittest.TestCase):
    def test_a_retry_replaces_only_the_product_it_retried(self):
        from bench import report
        rows = [dict(subject='s1', cohort='tor', label='vpn', attempt=0, products=dict(a=dict(blocked=False), b=dict(blocked=True))),
                dict(subject='s1', cohort='tor', label='vpn', attempt=1, products=dict(a=dict(blocked=True)))]
        final = report.headline_rows(dict(rows=rows))
        self.assertEqual(final[0]['products'], dict(a=dict(blocked=True), b=dict(blocked=True)))


class SharedPacing(unittest.TestCase):
    def test_call_site_full_window_and_after_join_plugins(self):
        from bench import pacing
        pacing._shared.clear()
        windows = [pacing.watch('connection-guard-061', 4.0) for _ in range(pacing.CALIBRATION)]
        self.assertTrue(all(w == 4.0 for w in windows))                      # calibration uses the site's full window
        self.assertEqual(pacing.watch('connection-guard-061', 4.0), pacing.OBSERVE_MIN_S)
        self.assertEqual(pacing.watch('connection-guard-061', 1.0), 1.0)      # never longer than the site's window
        late = [pacing.watch('kaurivpn', 8.0) for _ in range(pacing.CALIBRATION + 5)]
        self.assertTrue(all(w == 8.0 for w in late))                          # decides after the join: always full


class CommandSettle(unittest.TestCase):
    def run_command(self, lines_after):
        import asyncio, time
        from bench import servers

        class Stdin:
            def write(self, data): pass
            async def drain(self): pass

        server = servers.Server.__new__(servers.Server)
        server.lines = []
        server.process = type('P', (), {'stdin': Stdin()})()

        async def scenario():
            async def printer():
                for delay, text in lines_after:
                    await asyncio.sleep(delay)
                    server.lines.append((time.monotonic(), text))
            task = asyncio.ensure_future(printer())
            started = time.monotonic()
            out = await server.command('cg reload', settle=4.0)
            await task
            return time.monotonic() - started, out
        return asyncio.run(scenario())

    def test_answer_ends_the_wait_after_a_quiet_spell(self):
        took, out = self.run_command([(0.1, 'Reloaded.')])
        self.assertEqual(out, ['Reloaded.'])
        self.assertLess(took, 2.0)

    def test_silence_waits_the_full_settle(self):
        took, out = self.run_command([])
        self.assertEqual(out, [])
        self.assertGreaterEqual(took, 3.9)
