"""Conservative candidate acceptance from receipts; missing evidence never passes.

Usage: python3 -m bench.candidate_gate results/<run> [results/<other-run> ...]
This evaluates benchmark gates only. It does not authorize a release or replace
the owner's hosting-policy confirmation and migration/privacy review.
"""
import argparse,json
from pathlib import Path
from . import artifacts,products,report

CANDIDATE='connection-guard-candidate'
COMPARATORS=('connection-guard','foxgate','proxyshield','vpnguard')
FAULTS=('timeout','http_429','malformed','incomplete')
DECIDED={'ALLOW','DENY_LOGIN','DENY_CONFIG','DENY_PLAY'}

def valid_stop(record):
    stop=record.get('stop') or {}
    return (not record.get('harness_error') and not record.get('load_failure')
            and stop.get('exit')==0 and stop.get('jar_unchanged') is True
            and not stop.get('unexpected_plugin_jars'))

def evaluate(directories):
    gates=[]
    def gate(name, passed, details):
        gates.append(dict(name=name,passed=bool(passed),details=details))
    manifests=[json.loads((Path(d)/'manifest.json').read_text()) for d in directories]
    expected=products.adapter(CANDIDATE)['pins']['velocity'];pin=products.pins()[expected]
    relevant=[m for m in manifests if CANDIDATE in m['products']]
    bound=bool(relevant) and all(m.get('product_adapters',{}).get(CANDIDATE,{}).get('pins',{}).get('velocity')==expected
        and m['environment']['pins'].get(expected)==pin and m.get('harness_sha256') for m in relevant)
    gate('candidate-provenance',bound,dict(pin=expected,source=pin['source_commit'],sha256=pin['sha256']))
    expected_rows={r['id']:r for r in map(json.loads,(Path(artifacts.ROOT)/'datasets/detection-v1/dataset.public.jsonl').read_text().splitlines())}
    detection=report.merge_chunks(report.load(directories,'detection'))
    enforce=[r for r in detection if r.get('profile')=='enforce']
    rows=report.headline_rows(enforce[0]) if len(enforce)==1 else []
    complete=(len(rows)==len(expected_rows)==692 and {r['subject'] for r in rows}==set(expected_rows)
              and all(r['cohort']==expected_rows[r['subject']]['cohort'] and r['label']==expected_rows[r['subject']]['label']
                      and all(r.get('products',{}).get(p,{}).get('outcome') in DECIDED for p in (CANDIDATE,*COMPARATORS)) for r in rows))
    gate('matched-detection-complete',complete,dict(subjects=len(rows),expected=692,unresolved_or_missing_block_acceptance=True))
    cohorts={}
    quality=complete
    for cohort in report.COHORT_ORDER:
        subset=[r for r in rows if r['cohort']==cohort];n=len(subset)
        if not n or not complete:continue
        counts={p:sum(r['products'][p]['outcome'].startswith('DENY_') for r in subset) for p in (CANDIDATE,*COMPARATORS)}
        best=(max if cohort in report.POSITIVE else min)(counts[p] for p in COMPARATORS)
        passed=counts[CANDIDATE]>=best if cohort in report.POSITIVE else counts[CANDIDATE]<=best
        quality &= passed
        cohorts[cohort]=dict(n=n,blocked=counts,comparator_limit=best,passed=passed,
                            metric='detection' if cohort in report.POSITIVE else 'false_positive')
    gate('per-cohort-detection-and-false-positives',quality,cohorts)
    failures=[r for r in report.load(directories,'failure') if r.get('product')==CANDIDATE]
    faults={f:[r for r in failures if r.get('fault')==f] for f in FAULTS}
    tor_pass=all(len(v)==1 and valid_stop(v[0]) and v[0].get('during',{}).get('tor',{}).get('outcome','').startswith('DENY_')
                 and v[0]['during']['tor'].get('lookup_requests')==0 for v in faults.values())
    gate('local-tor-four-faults',tor_pass,{f:len(v) for f,v in faults.items()})
    perf=[r for r in report.load(directories,'performance') if r.get('product')==CANDIDATE and r.get('profile')=='enforce' and r.get('platform')=='velocity']
    rounds={r.get('round'):r for r in perf}
    complete_perf=(len(perf)==3 and set(rounds)=={0,1,2} and all(valid_stop(r) and r.get('process_alive') for r in perf))
    gate('performance-three-complete-rounds',complete_perf,dict(rounds=sorted(rounds)))
    for phase,budget in [('cold',300),('warm',4)]:
        passed=complete_perf and all(r.get(phase,{}).get('decision_ms',{}).get('n')==50
            and isinstance(r[phase]['decision_ms'].get('p50'),(int,float))
            and (r[phase]['decision_ms']['p50']<budget if phase=='cold' else r[phase]['decision_ms']['p50']<=budget) for r in perf)
        gate(phase+'-latency',passed,dict(p50_limit_ms=budget,values=[r.get(phase,{}).get('decision_ms',{}).get('p50') for r in perf]))
    checked=complete_perf and all(r.get('burst',{}).get('distinct_subjects')==1000
        and sum(r['burst'].get('outcomes',{}).values())==1000
        and r['burst'].get('completed_provider_verdicts_lower_bound',-1)>=950 for r in perf)
    gate('burst-concrete-checks-95-percent',checked,[r.get('burst',{}).get('completed_provider_verdicts_lower_bound') for r in perf])
    stampede=complete_perf and all(sum(r.get('stampede',{}).get('outcomes',{}).values())==100
        and set(r['stampede']['outcomes'])<=DECIDED and r['stampede'].get('lookup_requests',0)>=1
        and all(n<=1 for n in r['stampede'].get('lookup_requests_per_host',{}).values()) for r in perf)
    gate('stampede-one-request-per-provider',stampede,[r.get('stampede',{}).get('lookup_requests_per_host') for r in perf])
    reloads=[r for r in report.load(directories,'invalid-reload') if r.get('product')==CANDIDATE and r.get('platform')=='velocity']
    reload_ok=len(reloads)==1 and valid_stop(reloads[0])
    if reload_ok:
        body=reloads[0].get('result',{})
        reload_ok=(body.get('error_reported') and body.get('process_alive') and body.get('after_negative',{}).get('outcome')=='ALLOW'
            and all(body.get(k,{}).get('outcome','').startswith('DENY_') for k in ('before','after_positive','after_restore_positive')))
    gate('invalid-reload-protection',reload_ok,dict(receipts=len(reloads)))
    return dict(schema=1,benchmark_acceptance=all(g['passed'] for g in gates),gates=gates,
                release_authorized=False,limitations=['Point-in-time labelled endpoints; list circularity and unresolved cohorts remain visible.','Hosting-only review still requires owner confirmation before release.'])

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('directories',nargs='+');parser.add_argument('--output')
    args=parser.parse_args();result=evaluate(args.directories);text=json.dumps(result,indent=2)+'\n'
    if args.output:Path(args.output).write_text(text)
    else:print(text,end='')
    raise SystemExit(0 if result['benchmark_acceptance'] else 2)

if __name__=='__main__':main()
