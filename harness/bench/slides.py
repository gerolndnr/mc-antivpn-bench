"""Result slides for posts (Reddit, Discord): one finding per 1600x900 image, in the overview's design.

  GH_TOKEN=... python3 -m bench.slides --repo gerolndnr/mc-antivpn-bench --output docs/slides

Each slide states its finding as a sentence (the "action title"), shows one chart, and names its source and caveats
underneath. Titles are written from the data, so a later run produces correct slides without editing. The data is the
README overview's: every product's newest complete result per family (bench.latest). Benchmark branding only; products
are sorted by result and the accent marks the measured best value, as in the overview.
"""
import argparse
import html
import json
import os
import tempfile

from . import latest, overview
from .score import rank_key, score, score_range, unavailable

W, H = 1600, 900
REPO = 'github.com/gerolndnr/mc-antivpn-bench'
esc = html.escape


def css(theme):
    return overview.css(theme) + '''
html, body { height: 900px; }
body { padding: 0; }
.slide { position: relative; width: 1600px; height: 900px; padding: 46px 64px 0; display: flex; flex-direction: column; }
.slide-top { display: flex; justify-content: space-between; align-items: center; height: 30px; }
.slide-top .page { font-size: 14px; color: var(--fg-3); }
.slide h1 { margin-top: 34px; font-size: 42px; line-height: 1.12; letter-spacing: -0.035em; white-space: normal; max-width: 1360px;
  text-wrap: balance; }
.slide .sub { margin-top: 12px; font-size: 18px; white-space: normal; max-width: 1300px; }
.rule { margin-top: 26px; height: 1px; background: var(--line-strong); }
.body { flex: 1; min-height: 0; margin-top: 28px; }
.foot { min-height: 76px; padding-bottom: 22px; border-top: 1px solid var(--line); padding-top: 14px; display: grid; grid-template-columns: 1fr auto; gap: 24px;
  font-size: 13px; line-height: 1.5; color: var(--fg-3); }
.foot p + p { margin-top: 2px; }
.foot .src { text-align: right; white-space: nowrap; }
.panels { display: grid; gap: 40px; height: 100%; }
.panel h3 { font-size: 15px; font-weight: 500; color: var(--fg); letter-spacing: -0.005em; }
.panel h3 span { color: var(--fg-3); font-weight: 400; }
.hbars { margin-top: 20px; display: grid; gap: 14px; }
.hbar { display: grid; grid-template-columns: 250px 1fr 120px; align-items: center; gap: 16px; height: 46px; }
.hbar.narrow { grid-template-columns: 1fr 150px; }
.hbar .n { font-size: 16px; color: var(--fg); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.hbar .n sup { color: var(--fg-3); font-size: 12px; margin-left: 2px; }
.hbar .t { height: 34px; position: relative; background: var(--subtle); border-radius: 5px; }
.hbar .f { position: absolute; left: 0; top: 0; bottom: 0; border-radius: 5px; background: var(--bar); min-width: 3px; }
.hbar.best .f { background: var(--accent); }
.hbar .v { font-size: 18px; font-weight: 600; text-align: right; white-space: nowrap; }
.hbar .v small { display: block; font-size: 12px; font-weight: 400; color: var(--fg-3); }
.hbar.best .v { color: var(--accent-text); }
.hbar .na { font-size: 14px; color: var(--fg-3); font-weight: 400; }
table.m { width: 100%; border-collapse: collapse; font-size: 16px; table-layout: fixed; }
table.m th { font-size: 13px; font-weight: 500; color: var(--fg-3); text-align: center; padding: 0 6px 12px; white-space: normal;
  line-height: 1.3; vertical-align: bottom; }
table.m td:first-child { overflow: hidden; text-overflow: ellipsis; }
table.m th:first-child, table.m td:first-child { text-align: left; padding-left: 0; }
table.m td { border-top: 1px solid var(--line); height: 54px; text-align: center; padding: 0 8px; white-space: nowrap; }
table.m td:first-child { color: var(--fg); }
table.m td.count { font-weight: 600; font-size: 18px; }
table.m tr.lead td.count { color: var(--accent-text); }
.ok, .bad { display: inline-block; width: 22px; height: 22px; border-radius: 99px; position: relative; vertical-align: middle; }
.ok { background: var(--accent-soft); }
.ok::after { content: ""; position: absolute; left: 7px; top: 4px; width: 6px; height: 10px; border: solid var(--accent-text);
  border-width: 0 2.5px 2.5px 0; transform: rotate(45deg); }
.bad { background: var(--danger-soft); }
.bad::before, .bad::after { content: ""; position: absolute; left: 10px; top: 5px; width: 2.5px; height: 12px; background: var(--danger);
  border-radius: 2px; transform: rotate(45deg); }
.bad::after { transform: rotate(-45deg); }
.dash { color: var(--fg-3); }
.range { position: relative; height: 30px; }
.range .axis { position: absolute; left: 0; right: 0; top: 50%; height: 1px; background: var(--line); }
.range .span { position: absolute; top: 50%; height: 8px; transform: translateY(-50%); border-radius: 99px; background: var(--line-strong); }
.range .dot { position: absolute; top: 50%; width: 14px; height: 14px; transform: translate(-50%, -50%); border-radius: 99px;
  background: var(--fg-2); box-shadow: 0 0 0 3px var(--surface); }
.hbar.best .range .span { background: var(--accent-soft); }
.hbar.best .range .dot { background: var(--accent); }
.scale { display: grid; grid-template-columns: 250px 1fr 120px; gap: 16px; font-size: 12px; color: var(--fg-3); margin-top: 6px; }
.scale div { display: flex; justify-content: space-between; }
.sumbody { display: flex; flex-direction: column; height: 100%; }
.summary { display: grid; grid-template-columns: 1fr 1fr; gap: 26px 48px; }
.finding { border-top: 2px solid var(--fg); padding-top: 14px; }
.finding .k { font-size: 13px; color: var(--fg-3); text-transform: uppercase; letter-spacing: 0.06em; }
.finding p { margin-top: 8px; font-size: 23px; line-height: 1.3; letter-spacing: -0.015em; }
.tested { margin-top: auto; padding-bottom: 26px; display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.tested b { font-size: 13px; color: var(--fg-3); font-weight: 400; text-transform: uppercase; letter-spacing: 0.06em; margin-right: 8px; }
.tested span { height: 32px; padding: 0 14px; display: inline-flex; align-items: center; border: 1px solid var(--line-strong);
  border-radius: 999px; font-size: 15px; color: var(--fg-2); background: var(--surface); }
'''


def page(theme, n, total, title, sub, body, notes, source):
    notes_html = ''.join(f'<p>{n_}</p>' for n_ in notes)
    return f'''<!doctype html><html><head><meta charset="utf-8"><style>{css(theme)}</style></head><body>
<div class="slide"><div class="glow"></div>
<div class="slide-top"><div class="word"><i></i><span class="mono">mc-antivpn-bench</span></div><div class="page">{n} / {total}</div></div>
<h1>{title}</h1><p class="sub">{sub}</p><div class="rule"></div>
<div class="body">{body}</div>
<div class="foot"><div>{notes_html}</div><div class="src">Source: {esc(source)}<br>{REPO}</div></div>
</div></body></html>'''


def names_list(names):
    names = list(names)
    return names[0] if len(names) == 1 else ', '.join(names[:-1]) + ' and ' + names[-1]


def collect(dirs, labels):
    perf = overview.performance(dirs.get('performance', []))
    det = overview.detection(dirs.get('detection', []))
    fail = overview.failure(dirs.get('failure', []))
    func = overview.functional(dirs.get('functional', []))
    prov = overview.providers(dirs.get('providers', []))
    ids = set(det['products'] if det else []) | set(fail) | set(func)
    for p in perf.values():
        ids |= set(p)
    ids.discard('none')
    products = overview.newest_only(sorted(ids, key=lambda p: overview.PRODUCT_ORDER.index(p) if p in overview.PRODUCT_ORDER else 99))
    names = overview.product_names(products, labels)
    all_dirs = sorted({d for v in dirs.values() for d in v})
    return dict(perf=perf.get('velocity') or next(iter(perf.values()), {}), det=det, fail=fail, func=func, prov=prov,
                products=products, names=names, dates=overview.measured_dates(overview.manifests(all_dirs)))


def slide_detection(d):
    det, names = d['det'], d['names']
    cols = [p for p in det['products'] if p in d['products']]
    catch = [c for c, _ in overview.CATCH if c in det['cohorts']]
    spare = [c for c, _ in overview.SPARE if c in det['cohorts']]
    n_bad = sum(det['cohorts'][c]['n'] for c in catch)
    n_good = sum(det['cohorts'][c]['n'] for c in spare)
    blocked = {p: sum(det['cohorts'][c]['blocked'][p] for c in catch) for p in cols}
    refused = {p: sum(det['cohorts'][c]['blocked'][p] for c in spare) for p in cols}
    eligible = [p for p in cols if blocked[p] >= n_bad / 2]
    top_b = max(blocked.values())
    top_r = min(refused[p] for p in eligible)
    lead_b = [p for p in cols if blocked[p] == top_b]
    lead_r = [p for p in eligible if refused[p] == top_r]
    order = sorted(cols, key=lambda p: (-blocked[p], refused[p]))
    marks, notes = {}, []
    for p in sorted(det.get('unnormalized', set())):
        if p in cols and blocked[p] < n_bad / 2:
            marks[p] = '*'
            notes.append(f'* {esc(names[p])}: measured without the free ProxyCheck key the others\' keyless requests got; its own free '
                         'quotas ran out after about 100 players. A keyed run for every plugin replaces this.')
    for p in cols:
        if overview.after_join(p):
            marks[p] = marks.get(p, '') + '†'
            notes.append(f'† {esc(names[p])} admits every player and kicks afterwards; its blocks are kicks of players already on the server.')
    max_r = max(max(refused.values()), 1)

    def rows(values, scale, best, unit_n, low):
        out = []
        for p in order:
            v = values[p]
            out.append(f'<div class="hbar {"best" if p in best else ""}"><div class="n">{esc(names[p])}<sup>{marks.get(p, "")}</sup></div>'
                       f'<div class="t"><div class="f" style="width:{100 * v / scale:.2f}%"></div></div>'
                       f'<div class="v">{v}<small>of {unit_n}</small></div></div>')
        return ''.join(out)
    same = set(lead_b) & set(lead_r)
    if same:
        title = f'{names_list(names[p] for p in same)} blocks the most bad addresses and wrongly refuses the fewest real players'
    else:
        title = (f'{names_list(names[p] for p in lead_b)} blocks the most bad addresses; '
                 f'{names_list(names[p] for p in lead_r)} wrongly refuses the fewest real players')
    spread = top_b - min(blocked[p] for p in eligible)
    sub = (f'{det["subjects"]} real addresses, each plugin as shipped without API keys. Among the plugins that block at least half, '
           f'blocking differs by {spread} addresses; wrong refusals differ by {max(refused[p] for p in eligible) - top_r}.')
    body = f'''<div class="panels" style="grid-template-columns: 1.25fr 1fr">
<div class="panel"><h3>Blocked <span>· VPN servers, Tor exits and public proxies · higher is better</span></h3><div class="hbars">{rows(blocked, n_bad, lead_b, n_bad, False)}</div></div>
<div class="panel"><h3>Wrongly refused <span>· home and mobile connections · lower is better</span></h3><div class="hbars">{''.join(
        f'<div class="hbar narrow {"best" if p in lead_r else ""}"><div class="t"><div class="f" style="width:{100 * refused[p] / max_r:.2f}%"></div></div>'
        f'<div class="v">{refused[p]}<small>of {n_good}</small></div></div>' for p in order)}</div></div></div>'''
    notes = ['Highlighted: the most blocked, and the fewest wrongly refused among plugins that block at least half.'] + notes[:2]
    notes.append('VPN and Tor rows show coverage for plugins that use the providers\' own lists, which also label these addresses.')
    return title, sub, body, notes[:4], f'detection, {d["dates"]}'


def slide_wave(d):
    perf, names = d['perf'], d['names']
    cols = [p for p in d['products'] if p in perf]
    timed = [p for p in cols if not overview.after_join(p)]
    looked = {p: perf[p]['checked'] or 0 for p in cols}
    total = max((perf[p]['subjects'] or 0) for p in cols) or 1000
    order = sorted(cols, key=lambda p: (overview.after_join(p), -looked[p]))
    nearly = [p for p in timed if looked[p] >= 0.95 * total]
    best_look = [p for p in timed if looked[p] == max(looked[q] for q in timed)]
    fastest = min(timed, key=lambda p: perf[p]['burst_p95'] if looked[p] >= 0.95 * max(looked[q] for q in timed) else 1e12)
    cap = 30000

    def t(v):
        return '30 s<small>timed out</small>' if v >= 29000 else overview.fmt_ms(v)
    rows = []
    for p in order:
        late = overview.after_join(p)
        rows.append(f'<div class="hbar {"best" if p in best_look else ""}"><div class="n">{esc(names[p])}{"<sup>†</sup>" if late else ""}</div>'
                    f'<div class="t"><div class="f" style="width:{100 * looked[p] / total:.2f}%"></div></div>'
                    f'<div class="v">{looked[p]:,}<small>of {total:,}</small></div></div>')
    times = []
    for p in order:
        late = overview.after_join(p)
        v = perf[p]['burst_p95']
        times.append(f'<div class="hbar narrow {"best" if p == fastest and not late else ""}"><div class="t"><div class="f" style="width:{0 if late else 100 * min(v, cap) / cap:.2f}%"></div></div>'
                     f'<div class="v">{"<span class=na>after join</span>" if late else t(v)}</div></div>')
    if len(nearly) == 1:
        title = f'In a wave of {total:,} new players, only {names[nearly[0]]} checked nearly every player; the others skipped {100 - round(100 * max(looked[p] for p in timed if p not in nearly) / total)}% or more'
    elif nearly:
        title = f'In a wave of {total:,} new players, {names_list(names[p] for p in nearly)} checked nearly every player'
    else:
        title = f'In a wave of {total:,} new players, no plugin checked nearly every player'
    sub = (f'{total:,} new players join a Velocity proxy in 20 seconds. Detection services are simulated with the same delay and each '
           'service\'s free-tier limit for every plugin. Median of three rounds.')
    body = f'''<div class="panels" style="grid-template-columns: 1.25fr 1fr">
<div class="panel"><h3>Players looked up <span>· at least one detection-service request · higher is better</span></h3><div class="hbars">{''.join(rows)}</div></div>
<div class="panel"><h3>Time until the plugin decides <span>· 95th percentile · lower is better</span></h3><div class="hbars">{''.join(times)}</div></div></div>'''
    notes = ['A player not looked up is let in unchecked (quota used up, queue full) or refused without a check.',
             'Fastest is marked only among plugins that looked up nearly as many players as the best.']
    if any(overview.after_join(p) for p in cols):
        notes.append('† Admits every player and checks afterwards, so its decision time is not comparable.')
    return title, sub, body, notes, f'performance, {d["dates"]}'


def slide_failure(d):
    fail, names = d['fail'], d['names']
    cols = [p for p in d['products'] if p in fail]
    faults = [(f, l) for f, l in overview.FAULTS if f != 'control' and any(f in fail[p] for p in cols)]
    passed = {p: sum(1 for f, _ in faults if (fail[p].get(f) or {}).get('ok')) for p in cols}
    order = sorted(cols, key=lambda p: -passed[p])
    full = [p for p in cols if passed[p] == len(faults)]
    head = ''.join(f'<th>{esc(l)}</th>' for _, l in faults)
    rows = ''.join(f'<tr class="{"lead" if p in full else ""}"><td>{esc(names[p])}</td>' + ''.join(
        f'<td>{overview.MARK[(fail[p].get(f) or {}).get("ok")]}</td>' for f, _ in faults) +
        f'<td class="count">{passed[p]} / {len(faults)}</td></tr>' for p in order)
    title = (f'{len(full)} of {len(cols)} plugins keep refusing VPN and Tor when every detection service fails; '
             f'{len(cols) - len(full)} let them in')
    sub = ('Every detection service a plugin uses is made to fail in one way at a time. A VPN, a Tor exit and a home player join '
           'during the outage. A check means the VPN and the Tor exit were still refused.')
    widths = '<colgroup><col style="width:300px">' + '<col>' * len(faults) + '<col style="width:120px"></colgroup>'
    body = f'<table class="m">{widths}<tr><th>Plugin</th>{head}<th>Passed</th></tr>{rows}</table>'
    notes = ['Plugins that pass keep their own lists (or a local Tor list) and refuse listed addresses without any lookup.',
             'Home players got in during every outage for every plugin; how long they waited is in the README overview.']
    return title, sub, body, notes, f'failure, {d["dates"]}'


def slide_platforms(d):
    func, names = d['func'], d['names']
    cols = [p for p in d['products'] if p in func]
    checks = [('Paper', lambda f: (f.get('platform') or {}).get('paper')), ('Folia', lambda f: (f.get('platform') or {}).get('folia')),
              ('Velocity', lambda f: (f.get('platform') or {}).get('velocity')), ('BungeeCord', lambda f: (f.get('platform') or {}).get('bungee')),
              ('Installs cleanly', lambda f: all_ok(f.get('clean-install'))), ('Blocks out of the box', lambda f: all_ok(f.get('out-of-box'))),
              ('Keeps settings on upgrade', lambda f: all_ok(f.get('upgrade'))), ('Survives a broken reload', lambda f: all_ok(f.get('invalid-reload'))),
              ('Never leaks API keys', lambda f: all_ok(f.get('secrets')))]
    table = {p: [check(func[p]) for _, check in checks] for p in cols}
    passed = {p: sum(1 for v in table[p] if v is True) for p in cols}
    applicable = {p: sum(1 for v in table[p] if v is not None) for p in cols}
    order = sorted(cols, key=lambda p: (-(passed[p] / max(1, applicable[p])), -passed[p]))
    full = [p for p in cols if passed[p] == applicable[p]]
    folia_fail = [p for p in cols if table[p][1] is False]
    head = ''.join(f'<th>{esc(l)}</th>' for l, _ in checks)
    rows = ''.join(f'<tr class="{"lead" if p in full else ""}"><td>{esc(names[p])}</td>' + ''.join(
        f'<td>{overview.MARK[v] if v is not None else "<span class=dash>n/a</span>"}</td>' for v in table[p]) +
        f'<td class="count">{passed[p]} / {applicable[p]}</td></tr>' for p in order)
    title = f'{len(full)} of {len(cols)} plugins pass every platform and release check'
    if len(folia_fail) >= len(cols) / 2:
        title += f'; {len(folia_fail)} do not run on Folia'
    sub = ('A VPN, a Tor exit, a home and a mobile player join on each platform; then a clean install, an upgrade with a changed '
           'setting, a reload with a broken config, and a scan of every request for leaked API keys.')
    widths = '<colgroup><col style="width:250px">' + '<col>' * len(checks) + '<col style="width:96px"></colgroup>'
    body = f'<table class="m" style="font-size:15px">{widths}<tr><th>Plugin</th>{head}<th>Passed</th></tr>{rows}</table>'
    notes = ['n/a: not applicable, e.g. no earlier release to upgrade from.',
             '"Blocks out of the box" fails where a plugin ships with blocking switched off; that can be a deliberate default.']
    return title, sub, body, notes, f'functional, {d["dates"]}'


def all_ok(values):
    values = [v for v in (values or []) if v is not None]
    return None if not values else all(values)


def slide_providers(d):
    prov = d['prov']
    services = sorted(prov['services'].items(), key=lambda x: rank_key(x[1]))
    shown = [(s, v) for s, v in services if not unavailable(v)][:8]
    lead_s, lead_v = shown[0]
    lo = min(score_range(v)[0] for _, v in shown)
    lo = max(0, int(lo // 10) * 10)
    span = 100 - lo
    pos = lambda x: f'{100 * (min(max(x, lo), 100) - lo) / span:.2f}%'
    overlap = [v['name'] for s, v in shown[1:] if score_range(v)[1] >= score_range(lead_v)[0]]
    rows = []
    for s, v in shown:
        a, b = score_range(v)
        tag = ' <sup>own</sup>' if v.get('own') else ''
        rows.append(f'<div class="hbar {"best" if s == lead_s else ""}"><div class="n">{esc(v["name"])}{tag}</div>'
                    f'<div class="range"><div class="axis"></div><div class="span" style="left:{pos(a)};right:calc(100% - {pos(b)})"></div>'
                    f'<div class="dot" style="left:{pos(score(v))}"></div></div>'
                    f'<div class="v">{score(v):.1f}<small>{v["caught"]}/{v["bad"]} · {v["refused"]}/{v["good"]}</small></div></div>')
    title = (f'{esc(lead_v["name"])} leads {len(services)} detection services, but {len(overlap)} others are within its 95 % range'
             if overlap else f'{esc(lead_v["name"])} leads {len(services)} detection services by more than the 95 % range')
    sub = (f'Score = 100 × (share caught − 3 × share of home players refused) − 5 per second of answer time. '
           f'{prov["meta"]["subjects"]} addresses sent straight to each service at its own quota. Top {len(shown)} shown.')
    body = f'''<div class="hbars">{''.join(rows)}</div><div class="scale"><div></div><div><span>{lo}</span><span>100</span></div><div></div></div>'''
    notes = ['Dot: score; bar: 95 % range from both shares. Values under the score: caught of 382 · refused of 310.']
    if any(v.get('own') for _, v in shown):
        notes.append('own: built by the benchmark\'s author. Its VPN and Tor lists come from the same sources that label those addresses; '
                     'its proxy list uses none of the proxy group\'s sources.')
    if any(v.get('from_date') for _, v in shown):
        notes.append('Services down in, or not part of, the newest run keep their result from an earlier run.')
    return title, sub, body, notes, f'providers, {(prov.get("meta") or {}).get("started", "")[:10]}'


def slide_summary(d, findings):
    names = d['names']
    tested = ''.join(f'<span>{esc(names[p])}</span>' for p in d['products'])
    cards = ''.join(f'<div class="finding"><div class="k">{esc(k)}</div><p>{t}</p></div>' for k, t in findings)
    title = f'{len(d["products"])} Minecraft anti-VPN plugins, measured on the same server'
    sub = ('Unmodified releases, a real Minecraft client, 692 labelled addresses, detection services replayed identically to every '
           'plugin. Method, adapters, raw data and every correction are public.')
    body = f'<div class="sumbody"><div class="summary">{cards}</div><div class="tested"><b>Tested</b>{tested}</div></div>'
    notes = ['Conflict of interest: the benchmark is built by the author of one of the tested plugins. Any plugin author can contest a result.',
             'Results describe this setup and dataset, not every server.']
    return title, sub, body, notes, f'mc-antivpn-bench, {d["dates"]}'


def build(dirs, labels):
    d = collect(dirs, labels)
    made = []
    for maker in (slide_detection, slide_wave, slide_failure, slide_platforms):
        try:
            made.append(maker(d))
        except (KeyError, ValueError, TypeError) as error:
            print(f'{maker.__name__} skipped: {type(error).__name__}: {error}')
    if d['prov']:
        made.append(slide_providers(d))
    findings = [(k, t) for k, (t, *_rest) in zip(['Detection', 'Join wave', 'Service outage', 'Platforms', 'Detection services'], made)]
    slides = [slide_summary(d, findings[:5])] + made
    return slides


def write(dirs, output, labels):
    os.makedirs(output, exist_ok=True)
    slides = build(dirs, labels)
    total, written = len(slides), []
    names = ['summary', 'detection', 'join-wave', 'outage', 'platforms', 'services']
    with tempfile.TemporaryDirectory() as tmp:
        for theme in ('light', 'dark'):
            for i, (title, sub, body, notes, source) in enumerate(slides, 1):
                page_html = page(theme, i, total, title, sub, body, notes, source)
                path = os.path.join(tmp, f'{i}-{theme}.html')
                open(path, 'w').write(page_html)
                png = os.path.join(output, f'{i:02d}-{names[i - 1] if i - 1 < len(names) else i}-{theme}.png')
                if not overview.render(path, png, H):
                    raise SystemExit('slides not rendered: no Chrome or Chromium found (set BENCH_CHROME)')
                written.append(png)
    return written


def main():
    p = argparse.ArgumentParser(prog='bench.slides')
    p.add_argument('--repo', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--labels', default=os.path.join(overview.ROOT, 'docs', 'overview', 'labels.json'))
    p.add_argument('--limit', type=int, default=60)
    a = p.parse_args()
    labels = json.load(open(a.labels)) if os.path.exists(a.labels) else {}
    with tempfile.TemporaryDirectory() as base:
        chosen, providers, profile = latest.select(a.repo, base, a.limit)
        dirs = latest.merge(chosen, providers, profile, base)
        for png in write(dirs, a.output, labels):
            print(png)


if __name__ == '__main__':
    main()
