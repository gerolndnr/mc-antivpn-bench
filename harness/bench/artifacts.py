"""Fetch and verify every binary the benchmark executes.

Server software and products are downloaded from their official distribution
points and verified against the checksum the distributor publishes (PaperMC fill:
SHA-256, Modrinth: SHA-512). BungeeCord's Jenkins publishes no checksum; its build
number is pinned and the SHA-256 observed at first download is locked in
`artifacts.lock.json`, so any later change fails loudly. Nothing here is
redistributed: the cache directory is git-ignored.
"""
import hashlib
import json
import os
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CACHE = os.path.join(ROOT, 'cache', 'artifacts')
LOCK = os.path.join(ROOT, 'artifacts.lock.json')
USER_AGENT = 'mc-antivpn-bench/1.0 (+https://github.com/gerolndnr/mc-antivpn-bench)'


def _get(url):
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response:
        return response.read()


def _digest(data, algorithm):
    return hashlib.new(algorithm, data).hexdigest()


def _lock():
    if os.path.exists(LOCK):
        with open(LOCK) as handle:
            return json.load(handle)
    return {}


def _save_lock(lock):
    with open(LOCK, 'w') as handle:
        json.dump(lock, handle, indent=2, sort_keys=True)
        handle.write('\n')


def fetch(entry):
    """entry: {id, url, sha256?|sha512?, filename}. Returns the verified local path."""
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, entry['id'], entry['filename'])
    lock = _lock()
    locked = lock.get(entry['id'])
    if os.path.exists(path):
        with open(path, 'rb') as handle:
            data = handle.read()
    else:
        data = _get(entry['url'])
    checks = [(algorithm, entry[algorithm]) for algorithm in ('sha256', 'sha512') if entry.get(algorithm)]
    if locked:
        checks.append(('sha256', locked['sha256']))
    if not checks:
        raise RuntimeError(f'{entry["id"]}: no published or locked checksum; refusing to trust it implicitly')
    for algorithm, expected in checks:
        actual = _digest(data, algorithm)
        if actual != expected:
            raise RuntimeError(f'{entry["id"]}: {algorithm} mismatch, expected {expected}, got {actual}')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, 'wb') as handle:
            handle.write(data)
    sha256 = _digest(data, 'sha256')
    if not locked or locked.get('sha256') != sha256:
        lock[entry['id']] = dict(sha256=sha256, url=entry['url'], filename=entry['filename'], bytes=len(data))
        _save_lock(lock)
    return path


def lock_unpublished(entry):
    """First fetch of an artifact without a published checksum (BungeeCord Jenkins).

    The observed SHA-256 is written to the lock; every later fetch must match it.
    """
    lock = _lock()
    if entry['id'] in lock:
        return fetch(entry)
    data = _get(entry['url'])
    path = os.path.join(CACHE, entry['id'], entry['filename'])
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as handle:
        handle.write(data)
    lock[entry['id']] = dict(sha256=_digest(data, 'sha256'), url=entry['url'], filename=entry['filename'],
                             bytes=len(data), note='no distributor checksum; locked at first download')
    _save_lock(lock)
    return path


def modrinth_file(project, version_number, prefer_loader=None):
    """Resolve an exact Modrinth version to its primary (or loader-specific) file and SHA-512."""
    versions = json.loads(_get(f'https://api.modrinth.com/v2/project/{project}/version'))
    matches = [v for v in versions if v['version_number'] == version_number]
    if not matches:
        raise RuntimeError(f'{project}: version {version_number} not on Modrinth')
    version = matches[0]
    files = version['files']
    chosen = next((f for f in files if f.get('primary')), files[0])
    return dict(id=f'{project}-{version_number}', url=chosen['url'], sha512=chosen['hashes']['sha512'],
                filename=chosen['filename'], version_id=version['id'], loaders=version['loaders'],
                game_versions=version['game_versions'], version_type=version['version_type'],
                published=version['date_published'])
