"""Detection, failure safety, performance and Redis outage families.

All four run products on the same platform build, with the same subjects, the same
recorded provider answers and the same fault or latency model. See METHODOLOGY.md
for the pre-registered decisions each family applies.
"""
import asyncio
import ipaddress
import json
import os
import random
import ssl
import statistics
import subprocess
import time
import urllib.parse

from . import mcclient, netguard, products
from .engine import Backend, Instance, measurement_rules, product_errors
from .interposer import CATCH_ALL_PORT
from .scenarios import PRIVATE, blocked, player

DETECTION_PLATFORM = 'velocity'
SUBJECT_INTERVAL_S = float(os.environ.get('BENCH_SUBJECT_INTERVAL_S', '5'))
OBSERVE_S = 8.0
SEED = 20261005


def dataset():
    return [json.loads(line) for line in open(PRIVATE)]


def by_cohort(items, cohort, n, offset=0):
    return [i for i in items if i['cohort'] == cohort][offset:offset + n]


class Sampler:
    """CPU seconds and RSS of one JVM, sampled from /proc once per second."""

    def __init__(self, pid):
        self.pid, self.samples, self.task = pid, [], None
        self.ticks = os.sysconf('SC_CLK_TCK')

    def read(self):
        try:
            fields = open(f'/proc/{self.pid}/stat').read().rsplit(')', 1)[1].split()
            cpu = (int(fields[11]) + int(fields[12])) / self.ticks
            rss = int(open(f'/proc/{self.pid}/statm').read().split()[1]) * os.sysconf('SC_PAGE_SIZE')
            return time.monotonic(), cpu, rss
        except (OSError, IndexError, ValueError):
            return None

    async def run(self):
        while True:
            sample = self.read()
            if sample:
                self.samples.append(sample)
            await asyncio.sleep(1.0)

    def start(self):
        self.task = asyncio.create_task(self.run())
        return self

    def stop(self):
        if self.task:
            self.task.cancel()
        if len(self.samples) < 2:
            return {}
        (t0, c0, _), (t1, c1, _) = self.samples[0], self.samples[-1]
        return dict(cpu_seconds=round(c1 - c0, 2), wall_seconds=round(t1 - t0, 2),
                    mean_cpu_cores=round((c1 - c0) / max(t1 - t0, 0.001), 3),
                    max_rss_mb=round(max(s[2] for s in self.samples) / 2 ** 20, 1))


def percentiles(values):
    values = sorted(v for v in values if v is not None)
    if not values:
        return {}
    pick = lambda q: values[min(len(values) - 1, max(0, int(round(q * (len(values) - 1)))))]
    return dict(n=len(values), p50=round(pick(0.5), 1), p90=round(pick(0.9), 1), p95=round(pick(0.95), 1),
                p99=round(pick(0.99), 1), max=round(values[-1], 1), mean=round(statistics.mean(values), 1))


def decision_ms(result):
    """Time from TCP connect to the product's admission decision as the player experiences it."""
    marks = result.get('marks', {})
    if result['outcome'] == 'DENY_LOGIN':
        return marks.get('decided')
    return marks.get('login_success') if result['outcome'] != 'TIMEOUT' else None


# ------------------------------------------------------------------ baselines
async def baseline_query(host, path, timeout=20):
    """HTTPS GET through the interposer (canary keys are swapped for real keys there)."""
    context = ssl.create_default_context(cafile='/work/state/ca/ca.pem')
    reader, writer = await asyncio.wait_for(asyncio.open_connection('127.0.0.1', CATCH_ALL_PORT, ssl=context,
                                                                    server_hostname=host), timeout)
    try:
        writer.write(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: mc-antivpn-bench-baseline\r\nX-Bench-Baseline: 1\r\n'
                     f'Connection: close\r\n\r\n'.encode())
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(), timeout)
    finally:
        writer.close()
    head, _, body = raw.partition(b'\r\n\r\n')
    status = int(head.split(b' ', 2)[1])
    return status, body


async def baselines(subject, canaries):
    ip = subject['ip']
    out = {}
    try:
        status, body = await baseline_query('proxycheck.io', f'/v2/{urllib.parse.quote(ip)}?vpn=1&asn=1&key='
                                                              f'{canaries["proxycheck"]}')
        data = json.loads(body).get(ip, {}) if status == 200 else {}
        out['proxycheck'] = dict(status=status, decision=None if not data else data.get('proxy') == 'yes',
                                 type=data.get('type'))
    except Exception as error:
        out['proxycheck'] = dict(status=None, decision=None, error=type(error).__name__)
    if not os.environ.get('VPNAPI_KEY'):
        out['vpnapi'] = dict(status=None, decision=None, error='not measured: VPNAPI_KEY not configured')
        return out
    try:
        status, body = await baseline_query('vpnapi.io', f'/api/{urllib.parse.quote(ip)}?key={canaries["vpnapi"]}')
        security = json.loads(body).get('security') if status == 200 else None
        out['vpnapi'] = dict(status=status, decision=None if not security else
                             any(security.get(k) for k in ('vpn', 'proxy', 'tor', 'relay')),
                             flags=security)
    except Exception as error:
        out['vpnapi'] = dict(status=None, decision=None, error=type(error).__name__)
    return out


# ------------------------------------------------------------------ detection
async def detection(runtime, recorder, canaries, product_ids, profile):
    items = dataset()
    rng = random.Random(SEED)
    order = items[:]
    rng.shuffle(order)
    limit = int(os.environ.get('BENCH_DETECTION_LIMIT') or '0')
    if limit:
        order = order[:limit]
    chunk = os.environ.get('BENCH_DETECTION_CHUNK', '')
    if chunk:
        # k/n: a stable, cohort-mixed share of the dataset, so one free key's daily quota covers
        # every product's lookups for that night's subjects (METHODOLOGY 7.1).
        k, n = (int(x) for x in chunk.split('/'))
        import hashlib
        order = [s for s in order if int(hashlib.sha256(s['id'].encode()).hexdigest(), 16) % n == k]
    backend = await Backend(DETECTION_PLATFORM).start()
    instances = []
    try:
        for slot, product_id in enumerate(product_ids):
            instance = Instance(runtime, product_id, DETECTION_PLATFORM, slot=slot, label=f'det-{product_id}')
            await instance.prepare(profile, canaries)
            instances.append(instance)
        runtime.rules(measurement_rules())
        starts = {}
        for instance in instances:
            starts[instance.product_id] = await instance.start()
        rows, retry = [], []

        async def measure(subject, attempt):
            mark = runtime.sequence()
            rotation = product_ids[attempt % len(product_ids):] + product_ids[:attempt % len(product_ids)]
            results = await asyncio.gather(*[
                mcclient.admit(i.port, subject['ip'], player(i.product_id), observe_s=OBSERVE_S)
                for i in sorted(instances, key=lambda i: rotation.index(i.product_id))])
            base = await baselines(subject, canaries)
            events = [e for e in runtime.events_since(mark) if e.get('subject_ip') == subject['ip']
                      and not e.get('baseline')]
            provider_errors = sorted({e['host'] for e in events if (e.get('status') or 0) in (429,) or
                                      (e.get('status') or 0) >= 500 or e.get('error')})
            row = dict(subject=subject['id'], cohort=subject['cohort'], label=subject['label'], attempt=attempt,
                       provider_errors=provider_errors, baselines=base, products={})
            for instance, result in zip(sorted(instances, key=lambda i: rotation.index(i.product_id)), results):
                row['products'][instance.product_id] = dict(outcome=result['outcome'], blocked=blocked(result['outcome']),
                                                            reason=(result.get('reason') or '')[:200],
                                                            decision_ms=decision_ms(result))
            return row

        for index, subject in enumerate(order):
            started = time.monotonic()
            row = await measure(subject, 0)
            if row['provider_errors']:
                retry.append(subject)
            rows.append(row)
            if index % 25 == 0:
                print(f'[detection {profile}] {index + 1}/{len(order)}', flush=True)
            await asyncio.sleep(max(0.0, SUBJECT_INTERVAL_S - (time.monotonic() - started)))
        if retry:
            await asyncio.sleep(90)
            # Product caches would answer a retry from the first (failed) attempt, so retries run
            # on freshly started instances with the same profile.
            for instance in instances:
                await instance.stop()
            for instance in instances:
                await instance.prepare(profile, canaries)
            for instance in instances:
                await instance.start()
            for subject in retry:
                started = time.monotonic()
                rows.append(await measure(subject, 1))
                await asyncio.sleep(max(0.0, SUBJECT_INTERVAL_S - (time.monotonic() - started)))
        record = dict(profile=profile, platform=DETECTION_PLATFORM, starts=starts, subjects=len(order),
                      retried=len(retry), rows=rows, chunk=chunk or None)
    finally:
        teardown = {}
        for instance in instances:
            if instance.server:
                teardown[instance.product_id] = await instance.stop()
                recorder.save('detection', f'{profile}-{instance.product_id}-console',
                              dict(product=instance.product_id, _console=instance.console(),
                                   errors=product_errors(instance.console(), instance.adapter, DETECTION_PLATFORM)[:50]))
        await backend.stop()
    record['teardown'] = teardown
    try:
        record['circularity'] = circularity('/work/state', product_ids)
    except Exception as error:
        record['circularity'] = dict(error=f'{type(error).__name__}: {error}')
    recorder.save('detection', profile + (f'-chunk{chunk.replace("/", "of")}' if chunk else ''), record)
    return record


# ------------------------------------------------------------------ failure safety
FAULTS = ['timeout', 'http_429', 'malformed', 'incomplete']


async def failure(runtime, recorder, canaries, product_ids, platform='velocity'):
    items = dataset()
    for product_id in product_ids:
        adapter = products.adapter(product_id)
        for fault in ['control'] + FAULTS:
            subjects = dict(vpn=by_cohort(items, 'commercial_vpn', 1, 3)[0], tor=by_cohort(items, 'tor', 1, 3)[0],
                            residential=by_cohort(items, 'residential', 1, 3)[0])
            backend = await Backend(platform).start()
            instance = Instance(runtime, product_id, platform, label=f'fail-{product_id}-{fault}')
            record = dict(product=product_id, platform=platform, fault=fault, lookup_hosts=adapter['lookup_hosts'])
            try:
                await instance.prepare('enforce', canaries)
                runtime.rules(measurement_rules())
                record['start'] = await instance.start()
                if fault != 'control':
                    runtime.rules(measurement_rules(extra=[dict(name=f'fault-{fault}', hosts=adapter['lookup_hosts'],
                                                                action='fault', fault=fault, hold_s=120)]))
                joins = {}
                for key, subject in subjects.items():
                    mark = runtime.sequence()
                    result = await mcclient.admit(instance.port, subject['ip'], player(product_id),
                                                  observe_s=OBSERVE_S, deadline_s=60)
                    calls = [e for e in runtime.events_since(mark) if e.get('host') in adapter['lookup_hosts']]
                    joins[key] = dict(subject=subject['id'], outcome=result['outcome'], blocked=blocked(result['outcome']),
                                      decision_ms=decision_ms(result), reason=(result.get('reason') or '')[:160],
                                      lookup_requests=len(calls))
                record['during'] = joins
                runtime.rules(measurement_rules())
                # Two re-joins of the VPN subject: 2 s after recovery (circuit breakers may still be open)
                # and 65 s after (any cooldown should have passed; a cached allow would still be served).
                for key, wait in (('after_recovery_vpn', 2), ('after_recovery_vpn_65s', 63)):
                    await asyncio.sleep(wait)
                    mark = runtime.sequence()
                    after = await mcclient.admit(instance.port, subjects['vpn']['ip'], player(product_id),
                                                 observe_s=OBSERVE_S)
                    calls = [e for e in runtime.events_since(mark) if e.get('host') in adapter['lookup_hosts']]
                    record[key] = dict(outcome=after['outcome'], blocked=blocked(after['outcome']),
                                       decision_ms=decision_ms(after), lookup_requests=len(calls))
                record['process_alive'] = instance.server.process.returncode is None
            except Exception as error:
                record['harness_error'] = f'{type(error).__name__}: {str(error)[:300]}'
            finally:
                runtime.rules(measurement_rules())
                record['stop'] = await instance.stop() if instance.server else None
                await backend.stop()
                console = instance.console()
                record['product_error_lines'] = len(product_errors(console, adapter, platform))
                record['_console'] = console
                record['_egress'] = instance.egress()
            recorder.save('failure', f'{product_id}-{fault}', record)
            print(f'[failure] {product_id} {fault}: ' + json.dumps({k: v['outcome'] for k, v in record.get('during', {}).items()}),
                  flush=True)


# ------------------------------------------------------------------ performance
LATENCY_MODEL = dict(median=120, p95=350)


def synthetic_subjects(items, count, seed):
    """Random addresses in the /12 networks around residential cohort addresses.

    Never inside a volunteer's own /24, and used only under template replay, so no
    lookup about them reaches a real provider.
    """
    rng = random.Random(seed)
    homes = sorted(i['ip'] for i in items if i['cohort'] == 'residential')
    own = {str(ipaddress.ip_network(ip + '/24', strict=False)) for ip in homes}
    out, seen = [], set()
    while len(out) < count:
        network = ipaddress.ip_network(rng.choice(homes) + '/12', strict=False)
        ip = network[rng.randint(256, network.num_addresses - 257)]
        if str(ipaddress.ip_network(f'{ip}/24', strict=False)) in own or not ip.is_global or str(ip) in seen:
            continue
        seen.add(str(ip))
        out.append(dict(id=f'synthetic-{len(out):04d}', ip=str(ip), label='non_vpn', cohort='synthetic'))
    return out


def template_rules(adapter, reference_ip):
    return measurement_rules(extra=[dict(name='template', hosts=adapter['lookup_hosts'], action='template',
                                         reference_ip=reference_ip, latency_ms=LATENCY_MODEL)],
                             normalize_quota=False)


async def run_joins(instance, subjects, concurrency=None, rate=None, observe_s=2.0):
    """Sequential (concurrency=None, rate=None), simultaneous (concurrency) or open-loop at `rate`/s."""
    if rate:
        tasks = []
        for index, subject in enumerate(subjects):
            tasks.append(asyncio.create_task(mcclient.admit(instance.port, subject['ip'], player('burst'),
                                                            observe_s=observe_s, deadline_s=60)))
            await asyncio.sleep(1.0 / rate)
        return await asyncio.gather(*tasks)
    if concurrency:
        return await asyncio.gather(*[mcclient.admit(instance.port, s['ip'], player('stamp'), observe_s=observe_s,
                                                     deadline_s=60) for s in subjects])
    return [await mcclient.admit(instance.port, s['ip'], player('seq'), observe_s=observe_s) for s in subjects]


def summarize(results, events, lookup_hosts, subjects=None):
    outcomes = {}
    for result in results:
        outcomes[result['outcome']] = outcomes.get(result['outcome'], 0) + 1
    calls = [e for e in events if e.get('host') in lookup_hosts]
    per_host = {}
    for event in calls:
        per_host[event['host']] = per_host.get(event['host'], 0) + 1
    distinct = {s['ip'] for s in subjects or []}
    looked_up = {e.get('subject_ip') for e in calls if e.get('subject_ip')} & distinct
    return dict(outcomes=outcomes, decision_ms=percentiles([decision_ms(r) for r in results]),
                distinct_subjects=len(distinct), subjects_with_lookup=len(looked_up),
                join_ms=percentiles([r.get('marks', {}).get('joined') for r in results]),
                lookup_requests=len(calls), lookup_requests_per_host=per_host)


async def performance(runtime, recorder, canaries, product_ids, platform='velocity', rounds=3, profile='enforce'):
    items = dataset()
    reference = by_cohort(items, 'residential', 1, 0)[0]
    burst_subjects = synthetic_subjects(items, 1000, SEED)
    seq_subjects = synthetic_subjects(items, 1100, SEED + 1)[1000:1100]
    stampede_ip = synthetic_subjects(items, 1101, SEED + 2)[-1]
    candidates = ['none'] + list(product_ids)
    for round_index in range(rounds):
        rotation = candidates[round_index % len(candidates):] + candidates[:round_index % len(candidates)]
        for product_id in rotation:
            record = dict(product=product_id, platform=platform, round=round_index, latency_model=LATENCY_MODEL,
                          profile=profile)
            backend = await Backend(platform).start() if platform in ('velocity', 'bungee') else None
            if product_id == 'none':
                adapter = dict(lookup_hosts=[], data_dir={platform: '-'}, id='none', name='none')
                instance = Instance(runtime, 'connection-guard', platform, label=f'perf-none-{round_index}')
                await instance.prepare('shipped', canaries)
                os.remove(os.path.join(instance.directory, 'plugins', instance.jar_name))
                import shutil
                shutil.rmtree(instance.data_dir, ignore_errors=True)
                instance.jar_sha256 = None
            else:
                adapter = products.adapter(product_id)
                instance = Instance(runtime, product_id, platform, label=f'perf-{product_id}-{round_index}')
                await instance.prepare(profile, canaries)
            try:
                # Reference answers for the template come from one real lookup per product.
                runtime.rules(measurement_rules())
                record['start'] = await instance.start()
                if product_id != 'none':
                    await mcclient.admit(instance.port, reference['ip'], player('ref'), observe_s=1)
                runtime.rules(template_rules(adapter, reference['ip']) if product_id != 'none' else measurement_rules())
                sampler = Sampler(instance.server.process.pid).start()
                for phase, subjects, kwargs in (
                        ('cold', seq_subjects[:50], {}),
                        ('warm', seq_subjects[:50], {}),
                        ('stampede', [stampede_ip] * 100, dict(concurrency=100)),
                        ('burst', burst_subjects, dict(rate=50))):
                    mark = runtime.sequence()
                    started = time.monotonic()
                    results = await run_joins(instance, subjects, **kwargs)
                    phase_record = summarize(results, runtime.events_since(mark), adapter['lookup_hosts'], subjects)
                    phase_record['wall_s'] = round(time.monotonic() - started, 1)
                    record[phase] = phase_record
                    print(f'[performance] r{round_index} {product_id} {phase}: {phase_record["outcomes"]} '
                          f'p50={phase_record["decision_ms"].get("p50")} req={phase_record["lookup_requests"]}', flush=True)
                record['resources'] = sampler.stop()
                record['process_alive'] = instance.server.process.returncode is None
            except Exception as error:
                record['harness_error'] = f'{type(error).__name__}: {str(error)[:300]}'
            finally:
                runtime.rules(measurement_rules())
                record['stop'] = await instance.stop() if instance.server else None
                if backend:
                    await backend.stop()
                console = instance.console()
                if product_id != 'none':
                    record['product_error_lines'] = len(product_errors(console, adapter, platform))
                record['_console'] = console
            recorder.save('performance', f'{platform}-{profile}-r{round_index}-{product_id}', record)


# ------------------------------------------------------------------ Redis outage
async def redis_outage(runtime, recorder, canaries, product_ids, platform='velocity'):
    items = dataset()
    residential, vpn = by_cohort(items, 'residential', 8, 10), by_cohort(items, 'commercial_vpn', 8, 10)
    pool = [s for pair in zip(residential, vpn) for s in pair]  # every step: one residential, one VPN
    for product_id in product_ids:
        adapter = products.adapter(product_id)
        if not adapter.get('redis'):
            recorder.save('redis', product_id, dict(product=product_id, applicable=False,
                                                    reason=adapter.get('redis_note')))
            continue
        redis = subprocess.Popen(['redis-server', '--port', '6379', '--bind', '127.0.0.1', '--save', '',
                                  '--appendonly', 'no'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(1)
        backend = await Backend(platform).start()
        instance = Instance(runtime, product_id, platform, label=f'redis-{product_id}')
        record = dict(product=product_id, platform=platform, steps={})
        subjects = iter(pool)

        async def step(name):
            outcome = []
            for _ in range(2):
                subject = next(subjects)
                result = await mcclient.admit(instance.port, subject['ip'], player(product_id), observe_s=4,
                                              deadline_s=60)
                outcome.append(dict(subject=subject['id'], label=subject['label'], outcome=result['outcome'],
                                    blocked=blocked(result['outcome']), decision_ms=decision_ms(result),
                                    reason=(result.get('reason') or '')[:160]))
            mark = len(instance.server.lines)
            record['steps'][name] = dict(joins=outcome, alive=instance.server.process.returncode is None)
            return mark

        try:
            await instance.prepare('enforce', canaries, extra_edits=adapter['redis']['edits'])
            runtime.rules(measurement_rules())
            record['start'] = await instance.start()
            await step('redis_up')
            netguard.block_port(6379, 'refuse')
            await step('redis_refused')
            netguard.block_port(6379, 'blackhole')
            await step('redis_blackholed')
            netguard.block_port(6379, 'clear')
            await asyncio.sleep(3)
            await step('redis_restored')
            await instance.stop()
            netguard.block_port(6379, 'refuse')
            await instance.prepare('enforce', canaries, extra_edits=adapter['redis']['edits'])
            record['start_while_down'] = await instance.start()
            await step('started_while_down')
        except StopIteration:
            record['harness_error'] = 'subject pool exhausted'
        except Exception as error:
            record['harness_error'] = f'{type(error).__name__}: {str(error)[:300]}'
        finally:
            netguard.block_port(6379, 'clear')
            record['stop'] = await instance.stop() if instance.server else None
            await backend.stop()
            redis.terminate()
            console = instance.console()
            record['product_error_lines'] = product_errors(console, adapter, platform)[:30]
            record['_console'] = console
        recorder.save('redis', product_id, record)


async def run(family, runtime, recorder, canaries, product_ids, platforms):
    keys = bool(os.environ.get('PROXYCHECK_KEY')) and bool(os.environ.get('VPNAPI_KEY'))
    if family in ('detection', 'all'):
        profiles = os.environ.get('BENCH_DETECTION_PROFILES') or 'enforce'
        for profile in profiles.split(','):
            if profile == 'free_keys' and not keys:
                print('[detection] free_keys profile skipped: PROXYCHECK_KEY/VPNAPI_KEY not set', flush=True)
                continue
            if profile == 'proxycheck_key' and not os.environ.get('PROXYCHECK_KEY'):
                print('[detection] proxycheck_key profile skipped: PROXYCHECK_KEY not set', flush=True)
                continue
            await detection(runtime, recorder, canaries, product_ids, profile)
    if family in ('failure', 'all'):
        await failure(runtime, recorder, canaries, product_ids)
    if family in ('redis', 'all'):
        await redis_outage(runtime, recorder, canaries, product_ids)
    if family in ('performance', 'all'):
        for platform in [p for p in ('velocity', 'paper') if p in platforms]:
            for profile in (os.environ.get('BENCH_PERF_PROFILES') or 'enforce').split(','):
                await performance(runtime, recorder, canaries, product_ids, platform=platform,
                                  rounds=int(os.environ.get('BENCH_PERF_ROUNDS') or '3'), profile=profile)


# ------------------------------------------------------------------ circularity
def parse_list(body):
    networks = []
    for line in body.decode('utf-8', 'replace').splitlines():
        token = line.strip().split()[0] if line.strip() else ''
        if not token or token.startswith(('#', ';', '//')):
            continue
        token = token.split('://')[-1]
        if token.count(':') == 1:  # ip:port
            token = token.split(':')[0]
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return networks


def circularity(runtime_state_dir, product_ids):
    """Share of each cohort already contained in the lists a product downloads (counts only)."""
    from .interposer import Interposer, Request
    probe = Interposer.__new__(Interposer)
    probe.secrets = {}
    import sqlite3
    db = sqlite3.connect(os.path.join(runtime_state_dir, 'answers.sqlite'))
    items = dataset()
    out = {}
    for product_id in product_ids:
        sources = products.adapter(product_id).get('list_sources', [])
        networks, used = [], []
        for url in sources:
            parts = urllib.parse.urlsplit(url)
            request = Request('GET', parts.path + ('?' + parts.query if parts.query else ''), 'HTTP/1.1',
                              [('Host', parts.hostname)], b'')
            key = probe.canonical(parts.scheme, parts.hostname, request)[0]
            row = db.execute('select body from answer where key=?', (key,)).fetchone()
            body, origin = (row[0], 'recorded during run') if row else (None, None)
            if body is None:
                # Products with a disk cache read lists loaded at install time; fetch the same URL once now.
                try:
                    from .dataset import fetch_with_retries
                    body, origin = fetch_with_retries(url, attempts=3), 'fetched at analysis time'
                except Exception as error:
                    used.append(dict(url=url, entries=None, note=f'unavailable: {type(error).__name__}'))
                    continue
            parsed = parse_list(body)
            networks += parsed
            used.append(dict(url=url, entries=len(parsed), origin=origin))
        v4 = [n for n in networks if n.version == 4]
        v6 = [n for n in networks if n.version == 6]
        counts = {}
        for item in items:
            address = ipaddress.ip_address(item['ip'])
            pool = v4 if address.version == 4 else v6
            hit = any(address in n for n in pool)
            entry = counts.setdefault(item['cohort'], [0, 0])
            entry[0] += int(hit)
            entry[1] += 1
        if not networks:
            out[product_id] = dict(lists=used, cohorts={}, note='no list content available')
            continue
        out[product_id] = dict(lists=used, cohorts={c: dict(listed=k, n=n) for c, (k, n) in counts.items()})
    return out
