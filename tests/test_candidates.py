import hashlib,tempfile,unittest
from pathlib import Path
from unittest.mock import patch,AsyncMock,MagicMock,call
from bench import artifacts,products,heavy,servers
from bench.__main__ import ALL_PRODUCTS
from bench.__main__ import prebuild_templates
from bench import candidate_gate

class AcceptanceContracts(unittest.TestCase):
    def fixtures(self):
        stop=dict(exit=0,jar_unchanged=True,unexpected_plugin_jars=[])
        subjects=[__import__('json').loads(line) for line in (Path(artifacts.ROOT)/'datasets/detection-v1/dataset.public.jsonl').read_text().splitlines()]
        rows=[dict(subject=s['id'],cohort=s['cohort'],label=s['label'],attempt=0,products={p:dict(outcome='DENY_LOGIN' if s['cohort'] in candidate_gate.report.POSITIVE else 'ALLOW') for p in (candidate_gate.CANDIDATE,*candidate_gate.COMPARATORS)}) for s in subjects]
        return {'detection':[dict(profile='enforce',rows=rows,subjects=692,retried=0,_path='synthetic')],
                'failure':[dict(product=candidate_gate.CANDIDATE,fault=f,stop=stop,during={'tor':dict(outcome='DENY_LOGIN',lookup_requests=0)}) for f in candidate_gate.FAULTS],
                'performance':[dict(product=candidate_gate.CANDIDATE,platform='velocity',profile='enforce',round=i,stop=stop,process_alive=True,
                    cold={'decision_ms':{'n':50,'p50':120}},warm={'decision_ms':{'n':50,'p50':3}},
                    burst={'distinct_subjects':1000,'outcomes':{'ALLOW':1000},'completed_provider_verdicts_lower_bound':1000},
                    stampede={'outcomes':{'ALLOW':100},'lookup_requests':1,'lookup_requests_per_host':{'api.ipquery.io':1}}) for i in range(3)],
                'invalid-reload':[dict(product=candidate_gate.CANDIDATE,platform='velocity',stop=stop,result=dict(error_reported=True,process_alive=True,
                    after_negative={'outcome':'ALLOW'},**{k:{'outcome':'DENY_LOGIN'} for k in ('before','after_positive','after_restore_positive')}))]}

    def evaluate(self,records):
        import json
        key=products.adapter(candidate_gate.CANDIDATE)['pins']['velocity']
        with tempfile.TemporaryDirectory() as tmp:
            manifest=dict(products=[candidate_gate.CANDIDATE],product_adapters={candidate_gate.CANDIDATE:products.adapter(candidate_gate.CANDIDATE)},environment={'pins':products.pins()},harness_sha256={'fixture':'synthetic'})
            (Path(tmp)/'manifest.json').write_text(json.dumps(manifest))
            with patch.object(candidate_gate.report,'load',side_effect=lambda directories,family:records[family]):
                return candidate_gate.evaluate([tmp])

    def test_complete_synthetic_evidence_passes_benchmark_but_never_authorizes_release(self):
        result=self.evaluate(self.fixtures());self.assertTrue(result['benchmark_acceptance']);self.assertFalse(result['release_authorized'])

    def test_http_attempts_do_not_satisfy_burst_concrete_checks(self):
        records=self.fixtures();records['performance'][0]['burst'].pop('completed_provider_verdicts_lower_bound')
        records['performance'][0]['burst']['subjects_with_lookup']=1000
        result=self.evaluate(records);self.assertFalse(result['benchmark_acceptance'])
        self.assertFalse(next(g for g in result['gates'] if g['name']=='burst-concrete-checks-95-percent')['passed'])

    def test_missing_subject_and_one_tor_failure_each_block_acceptance(self):
        for mutation in ('subject','tor'):
            records=self.fixtures()
            if mutation=='subject':records['detection'][0]['rows'].pop()
            else:records['failure'][2]['during']['tor']['outcome']='ALLOW'
            self.assertFalse(self.evaluate(records)['benchmark_acceptance'])

class SelectedTemplateContracts(unittest.IsolatedAsyncioTestCase):
    async def test_velocity_only_does_not_start_unused_backend_templates(self):
        runtime=MagicMock()
        with patch('bench.servers.build_paper_template',new_callable=AsyncMock) as backend,patch('bench.servers.build_proxy_template',new_callable=AsyncMock) as proxy:
            await prebuild_templates(runtime,['velocity'])
            self.assertEqual(backend.await_count,1)
            self.assertEqual(backend.await_args.args[:2],('paper','velocity-backend'))
            self.assertEqual(proxy.await_count,1)
            self.assertEqual(proxy.await_args.args[0],'velocity')

class CandidateContracts(unittest.TestCase):
    def test_published_baseline_and_default_selection_are_preserved(self):
        self.assertNotIn('connection-guard-candidate',ALL_PRODUCTS)
        self.assertEqual(set(products.adapter('connection-guard')['pins'].values()),{'connectionguard-0.5.0'})
        candidate=products.adapter('connection-guard-candidate')
        self.assertTrue(candidate['experimental'])
        for key in candidate['pins'].values():
            self.assertEqual(products.pins()[key]['release_status'],'unreleased')

    def test_staged_candidate_rejects_changed_bytes_and_external_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            data=b'controlled candidate bytes';sha=hashlib.sha256(data).hexdigest()
            file=Path(tmp)/'cache/candidates'/f'{sha}.jar';file.parent.mkdir(parents=True);file.write_bytes(data)
            pin=dict(release_status='unreleased',artifact=f'cache/candidates/{sha}.jar',sha256=sha,sha512=hashlib.sha512(data).hexdigest(),size=len(data))
            with patch.object(artifacts,'ROOT',tmp),patch.object(products,'pins',return_value={'candidate':pin}):
                self.assertEqual(products.jar('candidate'),str(file))
                file.write_bytes(b'different')
                with self.assertRaises(RuntimeError):products.jar('candidate')
                pin['artifact']='/tmp/arbitrary.jar'
                with self.assertRaises(ValueError):products.jar('candidate')

    def test_replay_respects_keyless_cap_and_prepares_both_backups(self):
        a=products.adapter('connection-guard-candidate')
        rules=heavy.template_rules(a,'192.0.2.1')['rules']
        proxy=next(r for r in rules if r['name']=='template-proxycheck.io')
        self.assertEqual(proxy['quota']['limit'],100)
        keyed=next(r for r in heavy.template_rules(a,'192.0.2.1','proxycheck_key')['rules'] if r['name']=='template-proxycheck.io')
        self.assertEqual(keyed['quota']['limit'],1000)
        self.assertEqual({r['host'] for r in a['template_seed_requests']},{'api.ipquery.io','ip-api.com'})
        self.assertEqual(a['bundled_lists'],['tor-exits.txt'])

    def test_completion_counter_does_not_count_attempts_or_warning_text(self):
        self.assertEqual(heavy.cg_provider_successes(['[INFO] ProxyCheck: attempts=10 successes=2 last=NETWORK', '[INFO] IP-API: attempts=12 successes=3', 'provider=IpQueryVpnProvider#1 reason=NETWORK; attempts=99 successes=99']),5)
        self.assertIsNone(heavy.cg_provider_successes(['allowed=1000 attempts=1000']))

    def test_read_only_template_copy_never_mutates_source_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);prior=root/'prior/templates/paper';prior.mkdir(parents=True)
            (prior/'libraries').mkdir();(prior/'libraries/a.jar').write_bytes(b'library')
            (prior/'server.properties').write_text('server-ip=127.0.0.1\n')
            template=root/'template';template.symlink_to(prior,target_is_directory=True)
            with patch.dict('os.environ',{'BENCH_READ_ONLY_TEMPLATES_ROOT':str(root/'prior/templates')}),patch.object(servers.subprocess,'run') as run:
                servers.fresh_copy(str(template),str(root/'run'))
                self.assertTrue((root/'run/libraries').is_symlink())
                self.assertEqual((root/'run/libraries/a.jar').read_bytes(),b'library')
                self.assertEqual(run.call_count,1)
                self.assertEqual(run.call_args.args[0][-1],str(root/'run'))
