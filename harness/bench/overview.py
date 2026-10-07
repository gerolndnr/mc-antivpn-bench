"""One overview graphic of every result in one or more public result directories.

  python3 -m bench.overview results/<run-a> [results/<run-b> ...] --output results/<name> [--label id=Text] [--theme light]

Writes overview.html (self-contained: fonts embedded, no network) and, when Chrome or Chromium is available,
overview.png at 2x. Every product is drawn the same way; the accent marks the best value in a row, whoever has it. Each plugin appears once,
in its newest pinned version (--all-versions shows older ones too).
Sections appear only for the families present. Reads public JSON only (no imports that need the container).
"""
import argparse
import base64
import glob
import html
import json
import os
import shutil
import statistics
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ASSETS = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'assets')
WIDTH = 1600
PRODUCT_ORDER = ['connection-guard-061', 'connection-guard-candidate', 'connection-guard', 'foxgate', 'proxyshield', 'vpnguard', 'kaurivpn',
                 'advancedantivpn']
CATCH = [('commercial_vpn', 'Commercial VPNs'), ('fresh_vpn', 'Newly added VPN servers'), ('vpn_v6', 'VPNs over IPv6'),
         ('tor', 'Tor exits'), ('proxy', 'Public proxies')]
SPARE = [('residential', 'Home connections'), ('residential_v6', 'Home connections, IPv6'), ('mobile_cgnat', 'Mobile networks')]
FAULTS = [('control', 'Services healthy'), ('timeout', 'Services time out'), ('http_429', 'Rate limited (429)'),
          ('malformed', 'Broken answers'), ('incomplete', 'Cut-off answers')]
PLATFORMS = [('paper', 'Paper'), ('folia', 'Folia'), ('velocity', 'Velocity'), ('bungee', 'BungeeCord')]
REDIS_STEPS = [('redis_up', 'Up'), ('redis_refused', 'Refused'), ('redis_blackholed', 'Black-holed'), ('redis_restored', 'Restored'),
               ('started_while_down', 'Start while down')]
esc = html.escape


# ------------------------------------------------------------------ data
def records(dirs, family):
    out = []
    for d in dirs:
        for path in sorted(glob.glob(os.path.join(d, family, '*.json'))):
            with open(path) as handle:
                out.append(json.load(handle))
    return out


def product_names(ids, labels):
    pins = {}
    for name in ('modrinth-pins.json', 'candidate-pins.json', 'private-pins.json'):
        path = os.path.join(ROOT, 'products', name)
        if os.path.exists(path):
            pins.update(json.load(open(path)))
    out = {'none': 'No anti-VPN plugin'}
    for pid in ids:
        if pid in labels:
            out[pid] = labels[pid]
            continue
        path = os.path.join(ROOT, 'products', f'{pid}.json')
        if not os.path.exists(path):
            out[pid] = pid
            continue
        adapter = json.load(open(path))
        name = adapter['name'].replace(' AntiVPN (Free)', '')
        pin = (adapter.get('pins') or {}).get('velocity') or next(iter((adapter.get('pins') or {'': ''}).values()))
        version = (pins.get(pin, {}).get('version') or '').split('+')[0]
        out[pid] = name if any(ch.isdigit() for ch in name) or not version else f'{name} {version}'
    return out


def pin_of(pid):
    path = os.path.join(ROOT, 'products', f'{pid}.json')
    if not os.path.exists(path):
        return {}
    adapter = json.load(open(path))
    pin = (adapter.get('pins') or {}).get('velocity') or next(iter((adapter.get('pins') or {'': ''}).values()))
    pins = {}
    for name in ('modrinth-pins.json', 'candidate-pins.json', 'private-pins.json'):
        if os.path.exists(os.path.join(ROOT, 'products', name)):
            pins.update(json.load(open(os.path.join(ROOT, 'products', name))))
    return pins.get(pin, {})


def version_key(version):
    """1.2.0-pre10 < 1.2.0: numbers first, then a release above any pre-release of the same number."""
    import re
    main, _, pre = (version or '').partition('-')
    numbers = tuple(int(x) for x in re.findall(r'\d+', main))
    return numbers, 0 if pre else 1, tuple(int(x) for x in re.findall(r'\d+', pre))


def newest_only(products):
    """One entry per plugin: the highest pinned version (a release wins a tie with a candidate of the same number)."""
    by_project = {}
    for pid in products:
        pin = pin_of(pid)
        key = pin.get('project') or pid
        rank = (version_key(pin.get('version')), pin.get('version_type') != 'candidate')
        if key not in by_project or rank > by_project[key][0]:
            by_project[key] = (rank, pid)
    keep = {pid for _, pid in by_project.values()}
    return [pid for pid in products if pid in keep]


def performance(dirs):
    """Per platform and product: the median across rounds of each value."""
    by = {}
    for r in records(dirs, 'performance'):
        if 'burst' not in r and 'cold' not in r:
            continue
        by.setdefault(r.get('platform', 'velocity'), {}).setdefault(r['product'], []).append(r)
    med = lambda xs: statistics.median(xs) if xs else None
    out = {}
    for platform, products in by.items():
        for pid, rounds in products.items():
            def m(phase, *keys):
                values = []
                for r in rounds:
                    v = r.get(phase) or {}
                    for k in keys:
                        v = v.get(k) if isinstance(v, dict) else None
                    if isinstance(v, (int, float)):
                        values.append(v)
                return med(values)
            out.setdefault(platform, {})[pid] = dict(
                rounds=len(rounds), burst_p95=m('burst', 'decision_ms', 'p95'), burst_p50=m('burst', 'decision_ms', 'p50'),
                checked=m('burst', 'subjects_with_lookup'), subjects=m('burst', 'distinct_subjects'),
                cold_p95=m('cold', 'decision_ms', 'p95'), warm_p50=m('warm', 'decision_ms', 'p50'),
                stampede=m('stampede', 'lookup_requests'), start=m('start', 'ready_s'),
                cpu=m('resources', 'cpu_seconds'), rss=m('resources', 'max_rss_mb'))
    return out


def detection(dirs):
    """The headline profile (proxycheck_key if measured, else enforce), chunks merged, final attempt per subject."""
    by = {}
    for r in records(dirs, 'detection'):
        if 'rows' in r:
            by.setdefault(r.get('profile', 'enforce'), []).extend(r['rows'])
    if not by:
        return None
    profile = 'proxycheck_key' if 'proxycheck_key' in by else 'enforce' if 'enforce' in by else next(iter(by))
    final = {}
    for row in by[profile]:
        if row['subject'] not in final or row['attempt'] >= final[row['subject']]['attempt']:
            final[row['subject']] = row
    rows = list(final.values())
    products = sorted({p for r in rows for p in r['products']}, key=lambda p: PRODUCT_ORDER.index(p) if p in PRODUCT_ORDER else 99)
    cohorts = {}
    for cid, _ in CATCH + SPARE:
        subset = [r for r in rows if r['cohort'] == cid]
        if subset:
            cohorts[cid] = dict(n=len(subset), blocked={p: sum(1 for r in subset if r['products'].get(p, {}).get('blocked')) for p in products})
    return dict(profile=profile, subjects=len(rows), products=products, cohorts=cohorts)


def failure(dirs):
    out = {}
    for r in records(dirs, 'failure'):
        during = r.get('during') or {}
        if r.get('fault') not in dict(FAULTS):
            continue
        ok = bool(during) and all(during.get(k, {}).get('blocked') for k in ('vpn', 'tor') if k in during) and 'vpn' in during
        home = during.get('residential') or {}
        out.setdefault(r['product'], {})[r['fault']] = dict(ok=ok, home_ms=home.get('decision_ms'), home_allowed=home.get('blocked') is False)
    return out


def expected(join):
    blocked = str(join.get('outcome', '')).startswith('DENY')
    return blocked == (join.get('label') != 'non_vpn')


def functional(dirs):
    out = {}
    for r in records(dirs, 'platform'):
        joins = r.get('result') if isinstance(r.get('result'), list) else []
        ok = None if r.get('harness_error') and not joins else (not r.get('load_failure') and bool(joins) and all(map(expected, joins)))
        out.setdefault(r['product'], {}).setdefault('platform', {})[r['platform']] = ok
    # Blocking out of the box is reported on its own: a shipped default that only reviews is a policy choice, and after an
    # upgrade the operator's previous settings decide, so neither counts against "installs" or "keeps settings".
    for family, check in (('clean-install', lambda r: None if r.get('harness_error') and not r.get('result') else
                           bool((r.get('result') or {}).get('data_dir_created')) and not r.get('load_failure')),
                          ('out-of-box', lambda r: None if not (r.get('result') or {}).get('joins') else
                           all(map(expected, r['result']['joins']))),
                          ('upgrade', lambda r: None if r.get('applicable') is False or r.get('marker_preserved') is None else
                           r.get('marker_preserved') is True),
                          ('invalid-reload', reload_ok),
                          ('secrets', lambda r: None if r.get('harness_error') else not (r.get('findings') or []))):
        for r in records(dirs, 'clean-install' if family == 'out-of-box' else family):
            out.setdefault(r['product'], {}).setdefault(family, []).append(check(r))
    return out


def reload_ok(r):
    result = r.get('result') or {}
    if not result:
        return None
    if not result.get('process_alive'):
        return False
    if not result['before']['outcome'].startswith('DENY'):
        return None
    return result['after_positive']['outcome'].startswith('DENY') and result['after_negative']['outcome'] == 'ALLOW'


def redis(dirs):
    out = {}
    for r in records(dirs, 'redis'):
        if r.get('applicable') is False:
            out[r['product']] = None
            continue
        steps = {}
        for sid, _ in REDIS_STEPS:
            step = (r.get('steps') or {}).get(sid)
            if step:
                steps[sid] = step.get('alive', True) is not False and all(
                    expected(j) and (j.get('decision_ms') or 0) < 10000 for j in step.get('joins', []))
        out[r['product']] = steps
    return out


def providers(dirs):
    for d in dirs:
        path = os.path.join(d, 'providers', 'summary.json')
        if os.path.exists(path):
            return json.load(open(path))
    return None


def manifests(dirs):
    out = []
    for d in dirs:
        path = os.path.join(d, 'manifest.json')
        if os.path.exists(path):
            out.append(json.load(open(path)))
    return out


# ------------------------------------------------------------------ drawing
def fmt_ms(v):
    if v is None:
        return '–'
    if v >= 29000:
        return '30 s'
    if v >= 1000:
        return f'{v / 1000:.1f} s'.replace('.0 s', ' s')
    return f'{v:.0f} ms'


def num(v):
    return '–' if v is None else f'{v:,.0f}'


MARK = {True: '<span class="ok" aria-label="pass"></span>', False: '<span class="bad" aria-label="fail"></span>', None: '<span class="na">–</span>'}


def best(values, low=True):
    vals = [v for v in values.values() if v is not None]
    if not vals:
        return set()
    target = min(vals) if low else max(vals)
    return {k for k, v in values.items() if v == target}


def css(theme):
    font = lambda name: base64.b64encode(open(os.path.join(ASSETS, 'fonts', name), 'rb').read()).decode()
    dark = dict(page='#000', surface='#0a0a0a', subtle='#161616', line='#1f1f1f', strong='#2e2e2e', fg='#ededed', fg2='#a1a1a1',
                fg3='#8f8f8f', accent='#10b981', accent_text='#34d399', soft='rgb(16 185 129 / 0.12)', bar='#3a3a3a', danger='#ff6369',
                danger_soft='rgb(255 99 105 / 0.12)', glow='rgb(16 185 129 / 0.08)')
    light = dict(page='#fafafa', surface='#fff', subtle='#f2f2f2', line='#ebebeb', strong='#d9d9d9', fg='#171717', fg2='#4d4d4d',
                 fg3='#6b6b6b', accent='#059669', accent_text='#047857', soft='rgb(5 150 105 / 0.10)', bar='#d4d4d4', danger='#c4232b',
                 danger_soft='rgb(196 35 43 / 0.08)', glow='rgb(5 150 105 / 0.05)')
    t = dark if theme == 'dark' else light
    return f'''
@font-face {{ font-family: Geist; src: url(data:font/woff2;base64,{font('geist.woff2')}) format("woff2"); font-weight: 100 900; }}
@font-face {{ font-family: "Geist Mono"; src: url(data:font/woff2;base64,{font('geist-mono.woff2')}) format("woff2"); font-weight: 100 900; }}
:root {{ --page:{t['page']}; --surface:{t['surface']}; --subtle:{t['subtle']}; --line:{t['line']}; --line-strong:{t['strong']};
  --fg:{t['fg']}; --fg-2:{t['fg2']}; --fg-3:{t['fg3']}; --accent:{t['accent']}; --accent-text:{t['accent_text']}; --accent-soft:{t['soft']};
  --bar:{t['bar']}; --danger:{t['danger']}; --danger-soft:{t['danger_soft']}; --glow:{t['glow']}; }}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
html, body {{ width: {WIDTH}px; background: var(--page); color: var(--fg); overflow: hidden; font-family: Geist, system-ui, sans-serif;
  -webkit-font-smoothing: antialiased; font-variant-numeric: tabular-nums; }}
body {{ position: relative; padding: 44px 56px 0; }}
.glow {{ position: absolute; width: 1100px; height: 700px; right: -300px; top: -260px; pointer-events: none;
  background: radial-gradient(closest-side, var(--glow), transparent); }}
.mono {{ font-family: "Geist Mono", ui-monospace, monospace; }}
header {{ position: relative; height: 236px; }}
.top {{ display: flex; justify-content: space-between; align-items: center; height: 34px; }}
.word {{ display: flex; align-items: center; gap: 10px; font-size: 17px; color: var(--fg-2); letter-spacing: -0.01em; }}
.word i {{ width: 18px; height: 18px; border-radius: 5px; border: 1.5px solid var(--fg-3); position: relative; }}
.word i::after {{ content: ""; position: absolute; left: 3px; right: 3px; bottom: 3px; height: 4px; border-radius: 1px; background: var(--accent); }}
.pill {{ height: 32px; padding: 0 14px; display: inline-flex; align-items: center; gap: 8px; border: 1px solid var(--line-strong);
  border-radius: 999px; color: var(--fg-2); font-size: 14px; background: var(--surface); white-space: nowrap; }}
.pill b {{ color: var(--fg); font-weight: 500; }}
.pill .dot {{ width: 7px; height: 7px; border-radius: 99px; background: var(--accent); }}
h1 {{ margin-top: 30px; font-size: 58px; line-height: 1.02; font-weight: 600; letter-spacing: -0.04em; white-space: nowrap; }}
.sub {{ margin-top: 14px; font-size: 18px; color: var(--fg-2); white-space: nowrap; }}
.legend {{ margin-top: 20px; display: flex; gap: 8px; }}
.legend span {{ height: 28px; padding: 0 12px; display: inline-flex; align-items: center; border: 1px solid var(--line);
  border-radius: 999px; font-size: 13.5px; color: var(--fg-2); background: var(--surface); white-space: nowrap; }}
.row2 {{ display: grid; gap: 16px; margin-top: 16px; }}
.card {{ background: var(--surface); border: 1px solid var(--line); border-radius: 14px; padding: 20px 24px; overflow: hidden; }}
.card h2 {{ font-size: 16.5px; font-weight: 500; letter-spacing: -0.01em; white-space: nowrap; display: flex; align-items: baseline; gap: 10px; }}
.card h2 small {{ font-size: 12px; color: var(--fg-3); font-weight: 400; text-transform: uppercase; letter-spacing: 0.06em; }}
.hint {{ margin-top: 4px; font-size: 13.5px; color: var(--fg-3); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.bars {{ margin-top: 18px; display: grid; gap: 12px; }}
.bar-row {{ display: grid; grid-template-columns: 210px 1fr 200px; align-items: center; gap: 16px; height: 34px; }}
.bar-row .name {{ font-size: 15px; color: var(--fg-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.track {{ height: 26px; position: relative; background: var(--subtle); border-radius: 6px; }}
.fill {{ position: absolute; left: 0; top: 0; bottom: 0; border-radius: 6px; background: var(--bar); min-width: 4px; }}
.bar-row.best .fill {{ background: var(--accent); }}
.bar-row.ref .fill {{ background: transparent; border: 1.5px dashed var(--line-strong); }}
.bar-row.ref .name {{ color: var(--fg-3); }}
.val {{ text-align: right; font-size: 18px; font-weight: 500; color: var(--fg); white-space: nowrap; }}
.val small {{ display: block; font-size: 12.5px; font-weight: 400; color: var(--fg-3); margin-top: 1px; }}
.bar-row.best .val {{ color: var(--accent-text); }}
table {{ width: 100%; border-collapse: collapse; margin-top: 14px; table-layout: fixed; }}
th {{ height: 58px; font-size: 13px; font-weight: 500; color: var(--fg-2); text-align: right; padding: 0 0 8px 8px; white-space: normal; overflow: hidden; line-height: 1.3; vertical-align: bottom; }}
th span {{ color: var(--fg-3); font-weight: 400; font-size: 12px; }}
th:first-child, td:first-child {{ text-align: left; }}
td {{ height: 36px; border-top: 1px solid var(--line); font-size: 14.5px; text-align: right; color: var(--fg-2); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
td:first-child {{ color: var(--fg); }}
td.best {{ color: var(--accent-text); font-weight: 500; }}
td.group {{ height: 30px; font-size: 11.5px; color: var(--fg-3); text-transform: uppercase; letter-spacing: 0.07em; border-top: none; padding-top: 8px; }}
tr.total td {{ border-top: 1px solid var(--line-strong); font-weight: 500; color: var(--fg); }}
tr.total td.best {{ color: var(--accent-text); }}
.cell {{ display: inline-flex; align-items: center; gap: 8px; justify-content: flex-end; }}
.mini {{ width: 46px; height: 5px; border-radius: 3px; background: var(--subtle); position: relative; display: inline-block; }}
.mini b {{ position: absolute; left: 0; top: 0; bottom: 0; border-radius: 3px; background: var(--bar); }}
td.best .mini b {{ background: var(--accent); }}
.ok, .bad {{ display: inline-block; width: 20px; height: 20px; border-radius: 99px; position: relative; vertical-align: middle; }}
.ok {{ background: var(--accent-soft); }}
.ok::after {{ content: ""; position: absolute; left: 7px; top: 4px; width: 5px; height: 9px; border: solid var(--accent-text); border-width: 0 2px 2px 0; transform: rotate(45deg); }}
.bad {{ background: var(--danger-soft); }}
.bad::before, .bad::after {{ content: ""; position: absolute; left: 9px; top: 5px; width: 2px; height: 10px; background: var(--danger); border-radius: 1px; }}
.bad::before {{ transform: rotate(45deg); }} .bad::after {{ transform: rotate(-45deg); }}
.na {{ color: var(--fg-3); }}
.frac {{ font-size: 12px; color: var(--fg-3); margin-left: 6px; }}
footer {{ position: relative; margin-top: 18px; height: 76px; padding-top: 14px; border-top: 1px solid var(--line); display: flex;
  justify-content: space-between; gap: 32px; font-size: 12.5px; color: var(--fg-3); line-height: 1.55; }}
footer b {{ color: var(--fg-2); font-weight: 500; }}
'''


def bar_card(title, hint, rows, low=True, cap=None, tag='', eligible=None):
    """rows: (key, name, value, label, note, ref). `eligible`: only these keys can be marked best."""
    values = {k: v for k, _, v, _, _, ref in rows if not ref and (eligible is None or k in eligible)}
    winners = best(values, low)
    top = max([v for _, _, v, _, _, _ in rows if v is not None] or [1])
    top = min(top, cap) if cap else top
    out = [f'<section class="card"><h2>{esc(title)}{f"<small>{esc(tag)}</small>" if tag else ""}</h2><p class="hint">{esc(hint)}</p><div class="bars">']
    for k, name, v, label, note, ref in rows:
        width = 0 if v is None else max(0.4, 100 * min(v, top) / top)
        cls = 'ref' if ref else 'best' if k in winners else ''
        out.append(f'<div class="bar-row {cls}"><span class="name">{esc(name)}</span><span class="track"><span class="fill" style="width:{width:.2f}%"></span></span>'
                   f'<span class="val">{esc(label)}{f"<small>{esc(note)}</small>" if note else ""}</span></div>')
    out.append('</div></section>')
    return ''.join(out), 72 + 46 * len(rows)


def table_card(title, hint, head, body, widths=None, tag=''):
    cols = ''.join(f'<col style="width:{w}">' for w in (widths or []))
    rows_html, height = [], 0
    for row in body:
        cls, cells = row
        rows_html.append(f'<tr class="{cls}">' + ''.join(cells) + '</tr>')
        height += 30 if cls == 'groupr' else 37
    html_ = (f'<section class="card"><h2>{esc(title)}{f"<small>{esc(tag)}</small>" if tag else ""}</h2><p class="hint">{esc(hint)}</p>'
             f'<table><colgroup>{cols}</colgroup><thead><tr>' + ''.join(f'<th>{header(h)}</th>' for h in head) + '</tr></thead><tbody>'
             + ''.join(rows_html) + '</tbody></table></section>')
    return html_, 40 + 22 + 14 + 58 + height + 4


def header(text):
    """Product names over two lines: name, then version."""
    head, _, tail = text.rpartition(' ')
    if head and tail[:1].isdigit():
        return f'{esc(head)}<br><span>{esc(tail)}</span>'
    return esc(text) + '<br><span>&nbsp;</span>' if text else ''



def td(text, cls=''):
    return f'<td class="{cls}">{text}</td>'


def build(dirs, labels=None, theme='dark', title=None, all_versions=False):
    """`dirs`: result folders, or {family: folders} so each family comes from its own runs (bench.latest)."""
    labels = labels or {}
    of = (lambda family: dirs.get(family, [])) if isinstance(dirs, dict) else (lambda family: dirs)
    perf, det, fail = performance(of('performance')), detection(of('detection')), failure(of('failure'))
    func, red, prov = functional(of('functional')), redis(of('redis')), providers(of('providers'))
    if isinstance(dirs, dict):
        dirs = sorted({d for folders in dirs.values() for d in folders})
    ids = set()
    for platform in perf.values():
        ids |= set(platform)
    ids |= set(det['products']) if det else set()
    ids |= set(fail) | set(func) | set(red)
    ids.discard('none')
    products = sorted(ids, key=lambda p: PRODUCT_ORDER.index(p) if p in PRODUCT_ORDER else 99)
    if not all_versions:
        products = newest_only(products)
    names = product_names(products, labels)
    ms = manifests(dirs)
    started = sorted(m['environment'].get('started', '') for m in ms if m.get('environment'))
    import datetime
    date = datetime.date.fromisoformat(started[0][:10]).strftime('%-d %B %Y') if started else ''
    rounds = max([e['rounds'] for p in perf.values() for e in p.values()] or [0])
    sections, height = [], 236 if products else 190

    def place(cards, columns):
        nonlocal height
        if not cards:
            return
        h = max(c[1] for c in cards)
        sections.append(f'<div class="row2" style="grid-template-columns:{columns};height:{h}px">' +
                        ''.join(c[0].replace('<section class="card">', f'<section class="card" style="height:{h}px">', 1) for c in cards) + '</div>')
        height += 16 + h

    # Speed
    platform = 'velocity' if 'velocity' in perf else next(iter(perf), None)
    if platform:
        p = perf[platform]
        rows = []
        for pid in products + ['none']:
            e = p.get(pid)
            if not e or e['burst_p95'] is None:
                continue
            checked = e['checked']
            note = (f'{num(checked)} of {num(e["subjects"])} checked' if pid != 'none' and e['subjects'] else '')
            rows.append((pid, names[pid], e['burst_p95'], fmt_ms(e['burst_p95']), note, pid == 'none'))
        # A fast answer that skipped most players is not the best answer: only plugins that checked the most players compete.
        most = max([p[k]['checked'] or 0 for k, *_ in rows if k != 'none'] or [0])
        card_a = bar_card('1,000 players join in 20 seconds', 'Time until the plugin decides, 95th percentile, among those that checked the most players.',
                          rows, low=True, cap=30000, tag=platform.capitalize() + (f' · median of {rounds} rounds' if rounds > 1 else ''),
                          eligible={k for k, *_ in rows if k != 'none' and (p[k]['checked'] or 0) >= 0.95 * most})
        metrics = [('Single join, p95', 'cold_p95', fmt_ms, True), ('Repeat join, p50', 'warm_p50', fmt_ms, True),
                   ('Lookups, 100 same-IP joins', 'stampede', num, True), ('Players checked in the wave', 'checked', num, False),
                   ('Start-up', 'start', lambda v: '–' if v is None else f'{v:.1f} s', True)]
        cols = [pid for pid in products if pid in p]
        body = []
        for label, key, f, low in metrics:
            vals = {pid: p[pid][key] for pid in cols}
            if all(v is None for v in vals.values()):
                continue
            w = best(vals, low)
            body.append(('', [td(esc(label))] + [td(f(vals[pid]), 'best' if pid in w else '') for pid in cols]))
        card_b = table_card('Everyday joins', 'Same simulated services, same delays and free-tier limits for every plugin.',
                            [''] + [names[pid] for pid in cols], body, ['30%'] + [f'{70 / max(1, len(cols)):.2f}%'] * len(cols))
        place([card_a, card_b], '1fr 1fr')

    # Detection
    if det and det['cohorts']:
        cols = [pid for pid in det['products'] if pid in products]
        body, totals = [], {}
        for group, cohorts, low in (('Should be blocked', CATCH, False), ('Should get in', SPARE, True)):
            present = [(cid, label) for cid, label in cohorts if cid in det['cohorts']]
            if not present:
                continue
            body.append(('groupr', [f'<td class="group" colspan="{1 + len(cols)}">{group}{" · higher is better" if not low else " · fewer refused is better"}</td>']))
            for cid, label in present:
                c = det['cohorts'][cid]
                w = best(c['blocked'], low)
                cells = [td(f'{esc(label)}<span class="frac">{c["n"]}</span>')]
                for pid in cols:
                    k = c['blocked'][pid]
                    share = k / c['n'] if c['n'] else 0
                    cells.append(td(f'<span class="cell">{k}<span class="mini"><b style="width:{100 * share:.1f}%"></b></span></span>', 'best' if pid in w else ''))
                body.append(('', cells))
            n = sum(det['cohorts'][cid]['n'] for cid, _ in present)
            tot = {pid: sum(det['cohorts'][cid]['blocked'][pid] for cid, _ in present) for pid in cols}
            w = best(tot, low)
            body.append(('total', [td(('Blocked' if not low else 'Refused') + f' of {n}')] + [td(str(tot[pid]), 'best' if pid in w else '') for pid in cols]))
        profile = {'enforce': 'as shipped, no API keys', 'proxycheck_key': 'same free ProxyCheck key for every plugin',
                   'free_keys': 'free keys'}.get(det['profile'], det['profile'])
        place([table_card('Detection and false positives', f'{num(det["subjects"])} real addresses, {profile}. Each number: addresses blocked.',
                          [''] + [names[pid] for pid in cols], body, ['28%'] + [f'{72 / max(1, len(cols)):.2f}%'] * len(cols))], '1fr')

    # Reliability, Redis
    cards = []
    if fail:
        cols = [pid for pid in products if pid in fail]
        body = []
        for fid, label in FAULTS:
            if not any(fid in fail[pid] for pid in cols):
                continue
            body.append(('', [td(esc(label))] + [td(MARK[fail[pid][fid]['ok']] if fid in fail[pid] else MARK[None]) for pid in cols]))
        home = {pid: (fail[pid].get('timeout') or {}).get('home_ms') for pid in cols}
        if any(v is not None for v in home.values()):
            w = best(home, True)
            body.append(('total', [td('Home login while timing out')] + [td(fmt_ms(home[pid]), 'best' if pid in w else '') for pid in cols]))
        cards.append(table_card('When detection services fail', 'VPN and Tor still refused while every service fails this way.',
                                [''] + [names[pid] for pid in cols], body, ['34%'] + [f'{66 / max(1, len(cols)):.2f}%'] * len(cols)))
    if red:
        cols = products  # plugins the Redis run did not cover show as not measured
        red = {pid: red.get(pid, {}) for pid in products}
        body = []
        for sid, label in REDIS_STEPS:
            if not any(red[pid] and sid in red[pid] for pid in cols):
                continue
            body.append(('', [td(esc(label))] + [td(MARK[red[pid][sid]] if red[pid] and sid in red[pid] else
                                                   ('<span class="na">no Redis</span>' if red[pid] is None else MARK[None])) for pid in cols]))
        if body:
            body.append(('', [td('<span class="na">– not measured in this run</span>')] + [td('') for _ in cols]))
        cards.append(table_card('Redis outage', 'Correct decisions in under 10 s while the shared cache is down.',
                                [''] + [names[pid] for pid in cols], body, ['28%'] + [f'{72 / max(1, len(cols)):.2f}%'] * len(cols)))
    place(cards, ' '.join(['1fr'] * len(cards)))

    # Platforms and release quality
    if func:
        cols = [pid for pid in products if pid in func]
        body = []
        for key, label in PLATFORMS:
            if not any(key in (func[pid].get('platform') or {}) for pid in cols):
                continue
            body.append(('', [td(label)] + [td(MARK[(func[pid].get('platform') or {}).get(key)]) for pid in cols]))
        for family, label in (('clean-install', 'Installs cleanly'), ('out-of-box', 'Blocks VPN and Tor out of the box'),
                              ('upgrade', 'Upgrade keeps the operator\'s settings'),
                              ('invalid-reload', 'Broken config reload stays protected'), ('secrets', 'API keys never leak')):
            if not any(family in func[pid] for pid in cols):
                continue
            cells = [td(label)]
            for pid in cols:
                results = [r for r in func[pid].get(family, []) if r is not None]
                if not results:
                    cells.append(td(MARK[None]))
                else:
                    good = sum(results)
                    cells.append(td(f'{MARK[good == len(results)]}<span class="frac">{good}/{len(results)}</span>'))
            body.append(('', cells))
        place([table_card('Platforms and release quality', 'Fixed VPN, Tor, home and mobile joins on every platform; counts are platforms passed.',
                          [''] + [names[pid] for pid in cols], body, ['28%'] + [f'{72 / max(1, len(cols)):.2f}%'] * len(cols))], '1fr')

    # Detection services on their own
    if prov:
        services = sorted(prov['services'].items(), key=lambda x: -(x[1]['caught'] / max(1, x[1]['bad']) - 3 * x[1]['refused'] / max(1, x[1]['good'])))
        caught = {s: v['caught'] / v['bad'] if v['bad'] else None for s, v in services}
        # Fewest refusals only counts for services that also catch: a service that flags nothing refuses nobody.
        refused = {s: v['refused'] / v['good'] if v['good'] else None for s, v in services if v['bad'] and v['caught'] >= v['bad'] / 2}
        speed = {s: v['ms_p50'] for s, v in services if not v.get('local')}
        wc, wr, ws = best(caught, False), best(refused, True), best(speed, True)
        body = [('', [td(esc(v['name']) + (' <span class="frac">own, see note</span>' if v.get('own') else '')), td(f'{v["caught"]}/{v["bad"]}', 'best' if s in wc else ''),
                      td(f'{v["refused"]}/{v["good"]}', 'best' if s in wr else ''), td(f'{v["answered"]}/{v["subjects"]}'),
                      td('local' if v.get('local') else fmt_ms(v['ms_p50']), 'best' if s in ws else ''),
                      td('lists' if v.get('local') else 'key' if v['keyed'] else 'keyless')]) for s, v in services]
        if any(v.get('own') for _, v in services):
            body.append(('', [f'<td colspan="6" class="na" style="white-space:normal;font-size:12.5px;height:44px">Own: Connection Guard Intel is the '
                              'benchmark author\'s project. Its VPN and Tor lists come from the same sources that label those addresses, so '
                              'those numbers show coverage; its proxy list uses none of the proxy cohort\'s sources.</td>']))
        place([table_card('Detection services on their own', 'Every address sent straight to each service at its own rate limit and quota. Hosting alone is not a hit.',
                          ['Service', 'VPN, Tor, proxies caught', 'Home and mobile refused', 'Answered', 'Median time', 'Access'],
                          body, ['26%', '16%', '16%', '14%', '14%', '14%'], tag=f'{prov["meta"]["subjects"]} addresses')], '1fr')

    runs = ', '.join(sorted({str(m.get('run_id', '')).split('-')[0] for m in ms}))
    commits = sorted({(m['environment'].get('bench_commit') or '')[:7] for m in ms if m.get('environment')} - {''})
    status = 'Published run' if rounds >= 3 else 'Run'
    head = f'''<header><div class="top"><span class="word mono"><i></i>mc-antivpn-bench</span>
<span class="pill"><span class="dot"></span><b>{status}</b> · {esc(date)}{f" · {esc(platform.capitalize())}" if platform else ""}</span></div>
<h1>{esc(title or ('Anti-VPN plugins, measured.' if products else 'Detection services, measured.'))}</h1>
<p class="sub">{f"{len(products)} unmodified plugins on the same server, with the same players and the same simulated detection services." if products else "Detection services measured directly, without any plugin."}</p>
<div class="legend">{''.join(f'<span>{esc(names[p])}</span>' for p in products)}</div></header>'''.replace('<header>', '<header>' if products else '<header style="height:190px">')
    foot = f'''<footer><span><b>Method, raw data and every log:</b> github.com/gerolndnr/mc-antivpn-bench · runs {esc(runs)}{f" · commit {esc(', '.join(commits))}" if commits else ""}<br>
The accent marks the best value in each row. Results describe this setup and dataset, not every server.</span>
<span style="text-align:right">Conflict of interest: maintained by the author of Connection Guard.<br>Other plugin authors can contest adapters and results (METHODOLOGY 10).</span></footer>'''
    height += 18 + 76 + 40
    page = (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><title>mc-antivpn-bench overview</title><style>{css(theme)}'
            f'html, body {{ height: {height}px; }}</style></head><body><div class="glow"></div>{head}{"".join(sections)}{foot}'
            f'<script>document.fonts.ready.then(() => document.body.dataset.ready = "1")</script></body></html>')
    return page, height


def chrome():
    for candidate in (os.environ.get('BENCH_CHROME'), 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser',
                      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'):
        if candidate and (shutil.which(candidate) or os.path.exists(candidate)):
            return shutil.which(candidate) or candidate
    return None


def render(html_path, png_path, height):
    binary = chrome()
    if not binary:
        return False
    subprocess.run([binary, '--headless=new', '--disable-gpu', '--hide-scrollbars', '--force-device-scale-factor=2',
                    f'--window-size={WIDTH},{height}', '--virtual-time-budget=4000', f'--screenshot={os.path.abspath(png_path)}',
                    'file://' + os.path.abspath(html_path)], check=True, capture_output=True, timeout=120)
    return os.path.exists(png_path)


def write(dirs, output, labels=None, theme='dark', title=None, all_versions=False):
    os.makedirs(output, exist_ok=True)
    page, height = build(dirs, labels, theme, title, all_versions)
    html_path = os.path.join(output, 'overview.html')
    with open(html_path, 'w') as handle:
        handle.write(page)
    png = os.path.join(output, 'overview.png')
    try:
        rendered = render(html_path, png, height)
    except (subprocess.SubprocessError, OSError):
        rendered = False
    return html_path, png if rendered else None


def main():
    parser = argparse.ArgumentParser(prog='bench.overview')
    parser.add_argument('runs', nargs='+')
    parser.add_argument('--output', required=True)
    parser.add_argument('--label', action='append', default=[], help='product-id=Display name')
    parser.add_argument('--theme', choices=['dark', 'light'], default='dark')
    parser.add_argument('--title')
    parser.add_argument('--all-versions', action='store_true', help='also show older versions of the same plugin')
    args = parser.parse_args()
    html_path, png = write(args.runs, args.output, dict(x.split('=', 1) for x in args.label), args.theme, args.title, args.all_versions)
    print(html_path)
    print(png or 'overview.png not rendered: no Chrome or Chromium found (set BENCH_CHROME)')


if __name__ == '__main__':
    main()
