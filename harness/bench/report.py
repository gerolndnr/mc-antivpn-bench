"""Technical report from one or more public result directories.

  python3 -m bench.report results/<run-a> [results/<run-b> ...] --output results/<name>

Writes REPORT.md (tables, methods references, limitations), detection.csv,
performance.csv and failure.csv. Applies exactly the decision rules of
METHODOLOGY.md section 7; nothing here re-weights or combines results.
"""
import argparse
import csv
import glob
import json
import math
import os
import statistics

COHORT_ORDER = ['commercial_vpn', 'fresh_vpn', 'vpn_v6', 'tor', 'proxy', 'residential', 'mobile_cgnat',
                'residential_v6']
POSITIVE = {'commercial_vpn', 'fresh_vpn', 'vpn_v6', 'tor', 'proxy'}
NAMES = {'connection-guard': 'Connection Guard 0.5.0', 'foxgate': 'FoxGate 1.2.0-pre10',
         'proxyshield': 'ProxyShield 2.5.1', 'vpnguard': 'VPNGuard 1.2.0', 'proxycheck': 'ProxyCheck API',
         'vpnapi': 'VPNAPI API', 'none': 'no product (platform only)'}
PRODUCTS = ['connection-guard', 'foxgate', 'proxyshield', 'vpnguard']


def wilson(k, n, z=1.96):
    if not n:
        return None, None
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return max(0.0, centre - half), min(1.0, centre + half)


def pct(k, n):
    if not n:
        return 'n/a'
    low, high = wilson(k, n)
    return f'{100 * k / n:.0f} % ({k}/{n}, {100 * low:.0f}–{100 * high:.0f})'


def load(directories, family):
    out = []
    for directory in directories:
        for path in sorted(glob.glob(os.path.join(directory, family, '*.json'))):
            with open(path) as handle:
                record = json.load(handle)
            record['_path'] = os.path.relpath(path, os.path.dirname(directories[0]))
            console = path[:-5] + '.console.log'
            if os.path.exists(console) and record.get('product') in PRODUCTS and record.get('platform'):
                # Recompute with the current attribution rules (METHODOLOGY 7.7).
                from .engine import product_errors
                from .products import adapter
                record['product_error_lines'] = product_errors(open(console).read(), adapter(record['product']),
                                                               record['platform'])
            out.append(record)
    return out


# --------------------------------------------------------------- detection
def headline_rows(record):
    """Final attempt per subject (retries replace provider-error attempts)."""
    final = {}
    for row in record['rows']:
        if row['subject'] not in final or row['attempt'] >= final[row['subject']]['attempt']:
            final[row['subject']] = row
    return list(final.values())


def detection_tables(records, lines, csv_rows):
    for record in records:
        if 'rows' not in record:
            continue
        rows = headline_rows(record)
        profile = record['profile']
        products = [p for p in PRODUCTS if any(p in r['products'] for r in rows)]
        lines.append(f'\n### Detection and false positives — profile `{profile}` ({record["platform"]}, '
                     f'{len(rows)} subjects, {record["retried"]} re-measured after provider errors)\n')
        lines.append('Rate blocked, (blocked/n, Wilson 95 % interval). For VPN/Tor/proxy cohorts higher is better, '
                     'for residential/mobile cohorts lower is better. Undecided joins (timeout/error) are in the '
                     'denominator and listed below.\n')
        header = ['Cohort', 'Kind'] + [NAMES[p] for p in products] + [NAMES['proxycheck'], NAMES['vpnapi']]
        lines.append('| ' + ' | '.join(header) + ' |')
        lines.append('|' + '---|' * len(header))
        undecided = {p: 0 for p in products}
        for cohort in COHORT_ORDER:
            subset = [r for r in rows if r['cohort'] == cohort]
            if not subset:
                continue
            cells = [f'`{cohort}`', 'detection' if cohort in POSITIVE else 'false positive']
            for product in products:
                results = [r['products'][product] for r in subset if product in r['products']]
                k = sum(1 for r in results if r['blocked'])
                undecided[product] += sum(1 for r in results if r['outcome'] in ('TIMEOUT', 'ERROR'))
                cells.append(pct(k, len(results)))
                csv_rows.append(dict(profile=profile, cohort=cohort, product=product, blocked=k, n=len(results)))
            for baseline in ('proxycheck', 'vpnapi'):
                decided = [r['baselines'][baseline]['decision'] for r in subset
                           if r.get('baselines', {}).get(baseline, {}).get('decision') is not None]
                k = sum(1 for d in decided if d)
                cells.append(pct(k, len(decided)) if decided else 'not measured')
                csv_rows.append(dict(profile=profile, cohort=cohort, product=baseline, blocked=k, n=len(decided)))
            lines.append('| ' + ' | '.join(cells) + ' |')
        lines.append('\nUndecided joins (timeout or error): ' +
                     ', '.join(f'{NAMES[p]} {undecided[p]}' for p in products) + '.')
        timings = {p: [r['products'][p]['decision_ms'] for r in rows if p in r['products']
                       and r['products'][p]['decision_ms'] is not None] for p in products}
        lines.append('\nDecision time on live providers (connect → refusal or Login Success), median / p95 ms: ' +
                     ', '.join(f'{NAMES[p]} {statistics.median(v):.0f} / {sorted(v)[int(0.95 * (len(v) - 1))]:.0f}'
                               for p, v in timings.items() if v) + '.')
        circ = record.get('circularity') or {}
        if circ and 'error' not in circ:
            lines.append('\n**Circularity.** Share of each cohort that is already contained in the lists the product '
                         'downloads with its shipped configuration (same list content as during the run). A high value means '
                         'detection on that cohort can come from the same source as the ground truth.\n')
            listed = [p for p in products if circ.get(p, {}).get('lists')]
            if listed:
                lines.append('| Cohort | ' + ' | '.join(NAMES[p] for p in listed) + ' |')
                lines.append('|---|' + '---|' * len(listed))
                for cohort in COHORT_ORDER:
                    cells = []
                    for product in listed:
                        entry = circ[product]['cohorts'].get(cohort)
                        cells.append(pct(entry['listed'], entry['n']) if entry else '—')
                    lines.append(f'| `{cohort}` | ' + ' | '.join(cells) + ' |')
            others = [NAMES[p] for p in products if not circ.get(p, {}).get('lists')]
            if others:
                lines.append('\nNo downloaded lists in the shipped configuration: ' + ', '.join(others) + '.')
        lines.append(f'\nRaw rows: [`{record["_path"]}`]({record["_path"]}).')


# --------------------------------------------------------------- functional
def platform_table(records, lines):
    lines.append('\n### Platforms (`enforce`, four fixed subjects)\n')
    lines.append('| Product | Platform | Loaded | Decisions (Tor, VPN, residential, mobile) | Product error lines | '
                 'Clean stop |')
    lines.append('|---|---|---|---|---|---|')
    decisions = {}
    for record in records:
        joins = record.get('result') or []
        if isinstance(joins, list):
            decisions.setdefault(record['product'], {})[record['platform']] = \
                tuple('B' if j['outcome'].startswith('DENY') else 'A' if j['outcome'] == 'ALLOW' else '?' for j in joins)
    for record in records:
        joins = record.get('result') or []
        loaded = 'no' if record.get('load_failure') else ('not measured' if record.get('harness_error') else 'yes')
        mine = decisions.get(record['product'], {}).get(record['platform'])
        others = {d for p, d in decisions.get(record['product'], {}).items() if p != record['platform'] and d}
        parity = '' if not mine or not others else (' (parity ✓)' if mine in others else ' (**differs**)')
        text = ', '.join(j['outcome'] for j in joins) if isinstance(joins, list) and joins else \
            (record.get('harness_error') or '—')[:80]
        stop = record.get('stop') or {}
        clean = 'yes' if stop.get('exit') == 0 and stop.get('jar_unchanged') else ('—' if not stop else
                                                                                 f'exit {stop.get("exit")}')
        lines.append(f'| {NAMES.get(record["product"], record["product"])} | {record["platform"]} | {loaded} | '
                     f'{text}{parity} | {len(record.get("product_error_lines") or [])} | {clean} |')


def release_tables(clean, upgrades, reloads, lines):
    lines.append('\n### Clean install (`shipped`)\n')
    lines.append('| Product | Platform | Ready (s) | Data folder | Product error lines | Decisions (Tor, VPN) |')
    lines.append('|---|---|---|---|---|---|')
    for record in clean:
        result = record.get('result') or {}
        start = record.get('start') or {}
        joins = ', '.join(j['outcome'] for j in result.get('joins', [])) or (record.get('harness_error') or '—')[:60]
        lines.append(f'| {NAMES.get(record["product"])} | {record["platform"]} | '
                     f'{start.get("ready_s", 0):.0f} | {"yes" if result.get("data_dir_created") else "no"} | '
                     f'{len(record.get("product_error_lines") or [])} | {joins} |')
    lines.append('\n### Upgrade from the previous release\n')
    lines.append('| Product | Platform | From → to | Operator value kept | Product error lines | Decisions |')
    lines.append('|---|---|---|---|---|---|')
    for record in upgrades:
        if record.get('applicable') is False:
            continue
        joins = ', '.join(j['outcome'] for j in record.get('joins', [])) or (record.get('harness_error') or '—')[:60]
        kept = {True: 'yes', False: '**no**'}.get(record.get('marker_preserved'), 'not measured')
        lines.append(f'| {NAMES.get(record["product"])} | {record["platform"]} | {record.get("from_pin")} → '
                     f'{record.get("to_pin")} | {kept} | {len(record.get("product_error_lines") or [])} | {joins} |')
    lines.append('\n### Reload with a broken config\n')
    lines.append('| Product | Platform | Error visible | Fresh Tor after reload | Residential after reload | '
                 'Process alive | Class |')
    lines.append('|---|---|---|---|---|---|---|')
    for record in reloads:
        result = record.get('result') or {}
        if not result:
            lines.append(f'| {NAMES.get(record["product"])} | {record["platform"]} | not measured: '
                         f'{(record.get("harness_error") or "")[:60]} | | | | |')
            continue
        before = result['before']['outcome'].startswith('DENY')
        after = result['after_positive']['outcome'].startswith('DENY')
        negative = result['after_negative']['outcome']
        if not result.get('process_alive'):
            klass = 'crashed'
        elif not before:
            klass = 'not applicable (subject not blocked before reload)'
        elif after and negative == 'ALLOW':
            klass = 'kept protection'
        else:
            klass = '**dropped protection**'
        lines.append(f'| {NAMES.get(record["product"])} | {record["platform"]} | '
                     f'{"yes" if result.get("error_reported") else "**no**"} | {result["after_positive"]["outcome"]} | '
                     f'{negative} | {"yes" if result.get("process_alive") else "no"} | {klass} |')


def secrets_table(records, lines):
    lines.append('\n### Secret leakage (`free_keys` with canary keys)\n')
    lines.append('| Product | Platform | Findings | Key file mode |')
    lines.append('|---|---|---|---|')
    for record in records:
        findings = record.get('findings') or []
        text = '; '.join(f'{f["kind"]} ({f["secret"]}{", " + f.get("host", "") if f.get("host") else ""}'
                         f'{", " + f.get("path", "") if f.get("path") else ""})' for f in findings) or \
            ('none' if not record.get('harness_error') else 'not measured: ' + record['harness_error'][:60])
        modes = ', '.join(f'{k} {v}' for k, v in (record.get('configured_key_files') or {}).items())
        lines.append(f'| {NAMES.get(record["product"])} | {record["platform"]} | {text} | {modes} |')


# --------------------------------------------------------------- failure
def failure_table(records, lines, csv_rows):
    lines.append('\n### Failure safety (lookup APIs faulted, lists intact; Velocity, `enforce`)\n')
    lines.append('Outcome for (VPN, Tor, residential) during the fault; decision time of the residential join; '
                 'VPN join after recovery. Findings follow METHODOLOGY 7.2.\n')
    lines.append('| Product | Fault | During (VPN, Tor, res.) | Res. decision ms | Lookup requests | VPN after recovery (2 s / 65 s) | '
                 'Findings |')
    lines.append('|---|---|---|---|---|---|---|')
    control = {r['product']: r for r in records if r['fault'] == 'control'}
    for record in records:
        during = record.get('during') or {}
        if not during:
            lines.append(f'| {NAMES.get(record["product"])} | {record["fault"]} | not measured: '
                         f'{(record.get("harness_error") or "")[:60]} | | | | |')
            continue
        findings = []
        res_ms = during.get('residential', {}).get('decision_ms')
        if any((j.get('decision_ms') or 0) > 10000 or j['outcome'] == 'TIMEOUT' for j in during.values()):
            findings.append('hang')
        base = control.get(record['product'], {})
        if record['fault'] != 'control' and base.get('during'):
            early, late = record.get('after_recovery_vpn', {}), record.get('after_recovery_vpn_65s', {})
            if base['during']['vpn']['blocked'] and not early.get('blocked'):
                if late and not late.get('blocked'):
                    findings.append('unprotected 65 s after recovery' + (' (cached: no lookup)'
                                                                         if late.get('lookup_requests') == 0 else ''))
                else:
                    findings.append('recovery delay (admitted 2 s after recovery, blocked at 65 s)')
            base_calls = sum(j['lookup_requests'] for j in base['during'].values()) or 1
            calls = sum(j['lookup_requests'] for j in during.values())
            if calls > 3 * base_calls:
                findings.append(f'retry storm ({calls} vs {base_calls})')
        if not record.get('process_alive', True):
            findings.append('process died')
        lines.append(f'| {NAMES.get(record["product"])} | {record["fault"]} | '
                     f'{", ".join(during[k]["outcome"] for k in ("vpn", "tor", "residential") if k in during)} | '
                     f'{"—" if res_ms is None else f"{res_ms:.0f}"} | {sum(j["lookup_requests"] for j in during.values())} | '
                     f'{record.get("after_recovery_vpn", {}).get("outcome", "—")} / '
                     f'{record.get("after_recovery_vpn_65s", {}).get("outcome", "—")} | {", ".join(findings) or "—"} |')
        csv_rows.append(dict(product=record['product'], fault=record['fault'],
                             vpn=during.get('vpn', {}).get('outcome'), tor=during.get('tor', {}).get('outcome'),
                             residential=during.get('residential', {}).get('outcome'), residential_ms=res_ms,
                             findings=';'.join(findings)))


# --------------------------------------------------------------- performance
def performance_table(records, lines, csv_rows):
    if not records:
        return
    by = {}
    for record in records:
        by.setdefault((record['platform'] + ' / ' + record.get('profile', 'enforce'), record['product']), []).append(record)
    for platform in sorted({p for p, _ in by}):
        lines.append(f'\n### Performance — {platform} (template replay, provider latency median 120 / p95 350 ms)\n')
        lines.append('Median over rounds; brackets: min–max of the per-round value. Decision time in ms; '
                     '"req" = lookup requests that reached the (simulated) providers.\n')
        lines.append('| Product | Cold p50 | Cold p95 | Warm p50 / req | Stampede (100× one IP) req / outcomes | '
                     'Burst 1,000 @ 50/s p50 / p99 | Burst outcomes | Burst subjects checked | CPU s | Peak RSS MB |')
        lines.append('|---|---|---|---|---|---|---|---|---|---|')
        for product in ['none'] + PRODUCTS:
            rounds = by.get((platform, product))
            if not rounds:
                continue

            def agg(phase, field, sub=None):
                values = []
                for r in rounds:
                    value = (r.get(phase) or {}).get(field)
                    if sub and isinstance(value, dict):
                        value = value.get(sub)
                    if value is not None:
                        values.append(value)
                if not values:
                    return '—'
                med = statistics.median(values)
                return f'{med:.0f} [{min(values):.0f}–{max(values):.0f}]' if len(values) > 1 else f'{med:.0f}'

            def outcomes(phase):
                merged = {}
                for r in rounds:
                    for key, value in ((r.get(phase) or {}).get('outcomes') or {}).items():
                        merged[key] = merged.get(key, 0) + value
                return ', '.join(f'{k} {v}' for k, v in sorted(merged.items())) or '—'
            checked = [f"{(r.get('burst') or {}).get('subjects_with_lookup')}/{(r.get('burst') or {}).get('distinct_subjects')}"
                       for r in rounds if (r.get('burst') or {}).get('distinct_subjects')]
            checked_text = ', '.join(checked) or 'not recorded'
            cpu = [r['resources']['cpu_seconds'] for r in rounds if (r.get('resources') or {}).get('cpu_seconds')]
            rss = [r['resources']['max_rss_mb'] for r in rounds if (r.get('resources') or {}).get('max_rss_mb')]
            lines.append(f'| {NAMES[product]} | {agg("cold", "decision_ms", "p50")} | {agg("cold", "decision_ms", "p95")} | '
                         f'{agg("warm", "decision_ms", "p50")} / {agg("warm", "lookup_requests")} | '
                         f'{agg("stampede", "lookup_requests")} / {outcomes("stampede")} | '
                         f'{agg("burst", "decision_ms", "p50")} / {agg("burst", "decision_ms", "p99")} | '
                         f'{outcomes("burst")} | {checked_text} | {statistics.median(cpu):.0f} | {statistics.median(rss):.0f} |'
                         if cpu and rss else
                         f'| {NAMES[product]} | {agg("cold", "decision_ms", "p50")} | {agg("cold", "decision_ms", "p95")} | '
                         f'{agg("warm", "decision_ms", "p50")} / {agg("warm", "lookup_requests")} | '
                         f'{agg("stampede", "lookup_requests")} / {outcomes("stampede")} | '
                         f'{agg("burst", "decision_ms", "p50")} / {agg("burst", "decision_ms", "p99")} | '
                         f'{outcomes("burst")} | {checked_text} | — | — |')
            for r in rounds:
                for phase in ('cold', 'warm', 'stampede', 'burst'):
                    data = r.get(phase) or {}
                    csv_rows.append(dict(platform=platform, product=product, round=r['round'], phase=phase,
                                         p50=(data.get('decision_ms') or {}).get('p50'),
                                         p95=(data.get('decision_ms') or {}).get('p95'),
                                         p99=(data.get('decision_ms') or {}).get('p99'),
                                         lookup_requests=data.get('lookup_requests'),
                                         outcomes=json.dumps(data.get('outcomes'))))


def redis_table(records, lines):
    if not records:
        return
    lines.append('\n### Redis outage (Velocity, `enforce`)\n')
    lines.append('| Product | Up | Refused | Black-holed | Restored | Started while down |')
    lines.append('|---|---|---|---|---|---|')
    for record in records:
        if record.get('applicable') is False:
            lines.append(f'| {NAMES.get(record["product"])} | not applicable: {record.get("reason")} | | | | |')
            continue
        steps = record.get('steps', {})

        def cell(name):
            step = steps.get(name)
            if not step:
                return '—'
            return ', '.join(f'{j["label"]}:{j["outcome"]} {"" if j["decision_ms"] is None else str(round(j["decision_ms"])) + "ms"}'
                             for j in step['joins'])
        lines.append(f'| {NAMES.get(record["product"])} | {cell("redis_up")} | {cell("redis_refused")} | '
                     f'{cell("redis_blackholed")} | {cell("redis_restored")} | {cell("started_while_down")} |')


def write_csv(path, rows):
    if not rows:
        return
    with open(path, 'w', newline='') as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('runs', nargs='+')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    os.makedirs(args.output, exist_ok=True)
    manifests = [json.load(open(os.path.join(run, 'manifest.json'))) for run in args.runs
                 if os.path.exists(os.path.join(run, 'manifest.json'))]
    lines = ['# mc-antivpn-bench — technical report', '',
             'Generated from the public result directories listed under *Runs*. Method: '
             '[METHODOLOGY.md](../../METHODOLOGY.md). No combined score is computed; every table answers one question.']
    lines.append('\n## Runs\n')
    lines.append('| Run | Family | Host | Java | Commit | Keys | Duration |')
    lines.append('|---|---|---|---|---|---|---|')
    for m in manifests:
        env = m['environment']
        lines.append(f'| {m["run_id"]} | {m["family"]} | {env.get("host")} | {(env.get("java") or [""])[0]} | '
                     f'{(env.get("bench_commit") or "")[:10]}{" (dirty)" if env.get("bench_tree_dirty") else ""} | '
                     f'{", ".join(k for k, v in env["keys_present"].items() if v) or "none"} | '
                     f'{m.get("duration_s", 0) / 60:.0f} min |')
    detection_csv, failure_csv, performance_csv = [], [], []
    lines.append('\n## 1. Detection and false positives\n')
    detection = load(args.runs, 'detection')
    detection_tables([r for r in detection if 'rows' in r], lines, detection_csv)
    if not any('rows' in r for r in detection):
        lines.append('Not measured in these runs.')
    lines.append('\n## 2. Reliability\n')
    failure_table(load(args.runs, 'failure'), lines, failure_csv)
    redis_table(load(args.runs, 'redis'), lines)
    performance_table(load(args.runs, 'performance'), lines, performance_csv)
    lines.append('\n## 3. Platforms and release quality\n')
    platform_table(load(args.runs, 'platform'), lines)
    release_tables(load(args.runs, 'clean-install'), load(args.runs, 'upgrade'), load(args.runs, 'invalid-reload'),
                   lines)
    lines.append('\n## 4. Security\n')
    secrets_table(load(args.runs, 'secrets'), lines)
    lines.append('\n## Limitations\n')
    lines.append('See METHODOLOGY.md sections 6 and 7 for every limitation; the most important: residential proxies '
                 'are not measured; the proxy cohort is community-listed; RIPE Atlas hosts are not typical players; '
                 'timings come from a shared CI runner and support only large differences.')
    with open(os.path.join(args.output, 'REPORT.md'), 'w') as handle:
        handle.write('\n'.join(lines) + '\n')
    write_csv(os.path.join(args.output, 'detection.csv'), detection_csv)
    write_csv(os.path.join(args.output, 'failure.csv'), failure_csv)
    write_csv(os.path.join(args.output, 'performance.csv'), performance_csv)
    print(os.path.join(args.output, 'REPORT.md'))


if __name__ == '__main__':
    main()
