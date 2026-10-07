"""Bought products the benchmark may run but never publish (products/private-pins.json).

A paid JAR is licensed to its buyer and carries the buyer's marketplace id (SpigotMC writes it into every premium
download, and AdvancedAntiVPN prints it at startup). Neither the JAR, its hash nor that id may reach this public
repository or a public artifact. The owner keeps them in a private repository; CI downloads that release into
cache/private/plugins/ (git-ignored, never in the Actions cache):

  cache/private/plugins/<filename>     the JAR
  cache/private/plugins/private.json   {"sha256": {"<filename>": "<hex>"}, "redact": ["<buyer id>", ...]}

Every public result is masked with the `redact` values, and `python3 -m bench.private check <dir>` refuses an upload
that still contains one.

  python3 -m bench.private check results/<run-id>
"""
import hashlib
import json
import os
import re
import sys

from . import artifacts

PINS = os.path.join(artifacts.ROOT, 'products', 'private-pins.json')
DIRECTORY = os.environ.get('BENCH_PRIVATE_PLUGINS') or os.path.join(artifacts.ROOT, 'cache', 'private', 'plugins')
MASK = '<purchaser>'


def pins():
    if not os.path.exists(PINS):
        return {}
    with open(PINS) as handle:
        return json.load(handle)


def meta():
    path = os.path.join(DIRECTORY, 'private.json')
    if not os.path.exists(path):
        return {}
    with open(path) as handle:
        return json.load(handle)


def redact_values():
    """Longest first, so a value that contains another is masked whole."""
    return sorted({str(v) for v in meta().get('redact', []) if str(v)}, key=len, reverse=True)


def _pattern(value):
    """The whole value only: a numeric buyer id must not be masked inside a longer number (a timing, a port)."""
    return re.compile(r'(?<![0-9A-Za-z])' + re.escape(value) + r'(?![0-9A-Za-z])')


def redact(text):
    for value in redact_values():
        text = _pattern(value).sub(MASK, text)
    return text


def available(pin_key):
    pin = pins().get(pin_key)
    return bool(pin) and os.path.exists(os.path.join(DIRECTORY, pin['filename']))


def jar(pin_key):
    pin = pins()[pin_key]
    path = os.path.join(DIRECTORY, pin['filename'])
    if not os.path.exists(path):
        raise RuntimeError(f'{pin_key}: bought JAR not provided (cache/private/plugins/{pin["filename"]}; '
                           'CI: secret PRIVATE_PLUGINS_TOKEN, see docs/KEYS.md)')
    expected = meta().get('sha256', {}).get(pin['filename'])
    if not expected:
        raise RuntimeError(f'{pin_key}: no SHA-256 for {pin["filename"]} in cache/private/plugins/private.json')
    with open(path, 'rb') as handle:
        if hashlib.sha256(handle.read()).hexdigest() != expected:
            raise RuntimeError(f'{pin_key}: bought JAR does not match its private SHA-256')
    return path


def leaks(directory):
    """Files under `directory` that still contain a redact value (the values themselves are never printed)."""
    patterns = [re.compile(_pattern(v).pattern.encode()) for v in redact_values()]
    found = []
    if not patterns:
        return found
    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            with open(path, 'rb') as handle:
                data = handle.read()
            if any(p.search(data) for p in patterns):
                found.append(os.path.relpath(path, directory))
    return sorted(found)


def main():
    if len(sys.argv) != 3 or sys.argv[1] != 'check':
        sys.exit('usage: python3 -m bench.private check <directory>')
    found = leaks(sys.argv[2])
    if found:
        print('buyer data of a bought product found in public results:', file=sys.stderr)
        for path in found:
            print(f'  {path}', file=sys.stderr)
        sys.exit(1)
    print(f'no buyer data in {sys.argv[2]} ({len(redact_values())} values checked)')


if __name__ == '__main__':
    main()
