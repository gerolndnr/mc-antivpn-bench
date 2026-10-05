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
    def test_measurement_rules_block_telemetry_and_updates_for_everyone(self):
        rules = engine.measurement_rules()
        hosts = {h for rule in rules['rules'] if rule['action'] == 'deny' for h in rule['hosts']}
        for host in ('bstats.org', 'sentry.io', 'api.connectionguard.net', 'api.github.com', 'hub.spigotmc.org'):
            self.assertIn(host, hosts)

    def test_profiles_resolve_for_every_product(self):
        for product in ('connection-guard', 'foxgate', 'proxyshield', 'vpnguard'):
            adapter = json.load(open(os.path.join(ROOT, 'products', product + '.json')))
            for profile in ('shipped', 'enforce', 'free_keys'):
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
