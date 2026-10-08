"""Which of the dataset's Tor exits and public proxies were still listed when a run started (METHODOLOGY 3, "Stale
addresses").

The dataset is a snapshot: its Tor exits and proxies were listed when it was built, and exits and proxies come and go
within days. An address that had left its list before a run started is not counted for that run, in either
direction: a plugin or service that still flags it is not credited, one that does not is not docked.

- Tor: the Tor Project's exit list as published at the run start (the newest CollecTor exit-list file published
  before it). An exit not in that file had left the Tor network.
- Proxies: every proxy of the dataset is on proxifly's list (the one source list that is both updated and keeps its
  history). A proxy not in proxifly's newest version before the run start had dropped off it. vakhov's list has not
  changed since February 2026 and monosans keeps no history, so neither can say whether a proxy was still listed.

Each check is written to datasets/<name>/freshness/<start>.json with its evidence, so it can be re-checked without the
network; `python3 -m bench.freshness <start>...` computes missing ones.
"""
import argparse
import datetime
import io
import ipaddress
import json
import os
import re
import tarfile
import time
import urllib.error
import urllib.request

from . import artifacts

DATASET = os.path.join(artifacts.ROOT, 'datasets', 'detection-v1')
RECORDS = os.path.join(DATASET, 'freshness')
CACHE = os.path.join(artifacts.ROOT, 'cache', 'freshness')
COLLECTOR = 'https://collector.torproject.org'
PROXIFLY = ('proxifly/free-proxy-list', 'proxies/all/data.txt')
UA = 'mc-antivpn-bench freshness check (https://github.com/gerolndnr/mc-antivpn-bench)'
_ARCHIVES = {}  # month archive name -> bytes, fetched once per process
IP = re.compile(r'(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])')


def parse_time(value):
    t = datetime.datetime.fromisoformat(str(value).replace('Z', '+00:00'))
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


def fetch(url, cache_name=None, headers=None):
    path = os.path.join(CACHE, cache_name) if cache_name else None
    if path and os.path.exists(path):
        return open(path, 'rb').read()
    request = urllib.request.Request(url, headers={'User-Agent': UA, **(headers or {})})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=300) as response:
                data = response.read()
            break
        except (urllib.error.URLError, ConnectionError, TimeoutError):
            if attempt == 3:
                raise
            time.sleep(5 * (attempt + 1))
    if path:
        os.makedirs(CACHE, exist_ok=True)
        with open(path, 'wb') as handle:
            handle.write(data)
    return data


def exit_list_names(start):
    """(name, published) of every exit-list file of the month of `start` and the one before, archive and recent."""
    out = {}
    for month in sorted({start.strftime('%Y-%m'), (start.replace(day=1) - datetime.timedelta(days=1)).strftime('%Y-%m')}):
        name = f'exit-list-{month}.tar.xz'
        # A month's archive grows daily until the month is over: re-fetch it while it can still miss the start.
        # A finished month is cached for good, a running one for the day.
        done = (parse_time(f'{month}-01T00:00:00') + datetime.timedelta(days=32)).replace(day=1) <= start
        today = datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d')
        try:
            data = _ARCHIVES.get(name) or fetch(f'{COLLECTOR}/archive/exit-lists/{name}', name if done else f'{today}-{name}')
        except urllib.error.HTTPError:
            continue
        _ARCHIVES[name] = data
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
            for member in archive.getmembers():
                if member.isfile():
                    out[os.path.basename(member.name)] = ('archive', name, member.name)
    listing = fetch(f'{COLLECTOR}/recent/exit-lists/').decode()
    for name in set(re.findall(r'href="(\d{4}-\d{2}-\d{2}-\d{2}-\d{2}-\d{2})"', listing)):
        out.setdefault(name, ('recent', name, name))
    return {name: (datetime.datetime.strptime(name, '%Y-%m-%d-%H-%M-%S').replace(tzinfo=datetime.timezone.utc), where)
            for name, where in out.items()}


def exit_list_text(where):
    kind, container, member = where
    if kind == 'recent':
        return fetch(f'{COLLECTOR}/recent/exit-lists/{member}', f'recent-{member}').decode()
    data = _ARCHIVES[container]
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:xz') as archive:
        return archive.extractfile(member).read().decode()


def tor_exits(start):
    """The exit addresses of the newest exit-list file published before `start`, and that file's name."""
    names = {n: v for n, v in exit_list_names(start).items() if v[0] <= start}
    if not names:
        raise SystemExit(f'no Tor exit list published before {start.isoformat()}')
    name = max(names, key=lambda n: names[n][0])
    text = exit_list_text(names[name][1])
    return {line.split()[1] for line in text.splitlines() if line.startswith('ExitAddress ')}, name


def proxifly_ips(start):
    """The addresses on proxifly's list in its newest version before `start`, and that commit."""
    repo, path = PROXIFLY
    headers = {'Accept': 'application/vnd.github+json'}
    if os.environ.get('GITHUB_TOKEN'):
        headers['Authorization'] = f'Bearer {os.environ["GITHUB_TOKEN"]}'
    until = start.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    commits = json.loads(fetch(f'https://api.github.com/repos/{repo}/commits?path={path}&until={until}&per_page=1', headers=headers))
    if not commits:
        raise SystemExit(f'no proxifly version before {until}')
    sha, date = commits[0]['sha'], commits[0]['commit']['committer']['date']
    text = fetch(f'https://raw.githubusercontent.com/{repo}/{sha}/{path}', f'proxifly-{sha}.txt').decode()
    return set(IP.findall(text)), dict(commit=sha, date=date)


def subjects():
    """The dataset's Tor exits and proxies with their (public) addresses."""
    out = {}
    with open(os.path.join(DATASET, 'dataset.public.jsonl')) as handle:
        for line in handle:
            item = json.loads(line)
            if item['cohort'] in ('tor', 'proxy') and item.get('ip'):
                out[item['id']] = (item['cohort'], str(ipaddress.ip_address(item['ip'])))
    return out


def record_path(start):
    return os.path.join(RECORDS, start.astimezone(datetime.timezone.utc).strftime('%Y-%m-%dT%H%M') + '.json')


def check(start, network=True):
    """The freshness record for a run started at `start`: the stale subject ids and the evidence. None when it is not
    recorded and `network` is false."""
    start = parse_time(start)
    path = record_path(start)
    if os.path.exists(path):
        return json.load(open(path))
    if not network:
        return None
    exits, exit_file = tor_exits(start)
    proxies, version = proxifly_ips(start)
    stale = {}
    for sid, (cohort, ip) in sorted(subjects().items()):
        if cohort == 'tor' and ip not in exits:
            stale[sid] = 'not on the Tor exit list at the run start'
        if cohort == 'proxy' and ip not in proxies:
            stale[sid] = "not on proxifly's list at the run start"
    record = dict(started=start.isoformat(), tor=dict(source=f'{COLLECTOR}/ exit list {exit_file}', exits=len(exits)),
                  proxy=dict(source=f'github.com/{PROXIFLY[0]} {PROXIFLY[1]} at {version["commit"]}', committed=version['date'],
                             listed=len(proxies)),
                  stale=stale)
    os.makedirs(RECORDS, exist_ok=True)
    with open(path, 'w') as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write('\n')
    return record


def starts(dirs):
    """The start times of the runs in `dirs` (from their manifests)."""
    out = []
    for d in dirs:
        path = os.path.join(d, 'manifest.json')
        started = ((json.load(open(path)).get('environment') or {}).get('started')) if os.path.exists(path) else None
        if started:
            out.append(started)
    return sorted(set(out))


def stale(dirs):
    """Subject id -> reason for every Tor exit and proxy that was stale at the start of any run in `dirs`. With
    BENCH_FRESHNESS=off (tests, offline drawing), only already recorded checks are used."""
    network = os.environ.get('BENCH_FRESHNESS', 'on') != 'off'
    out = {}
    for started in starts(dirs):
        record = check(started, network)
        if record:
            for sid, reason in record['stale'].items():
                out.setdefault(sid, reason)
    return out


def main():
    parser = argparse.ArgumentParser(prog='bench.freshness')
    parser.add_argument('starts', nargs='+', help='run start times (ISO 8601)')
    for started in parser.parse_args().starts:
        record = check(started)
        tor = sum(1 for r in record['stale'].values() if 'Tor' in r)
        print(f'{record["started"]}: {tor} Tor exits and {len(record["stale"]) - tor} proxies stale '
              f'({record["tor"]["source"]}; {record["proxy"]["source"]})')


if __name__ == '__main__':
    main()
