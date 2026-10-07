"""Product artifacts and adapters (see products/*.json)."""
import json
import os

from . import artifacts, private

PINS = os.path.join(artifacts.ROOT, 'products', 'modrinth-pins.json')


CANDIDATES = os.path.join(artifacts.ROOT, 'products', 'candidate-pins.json')


def pins():
    with open(PINS) as handle:
        out = json.load(handle)
    if os.path.exists(CANDIDATES):
        with open(CANDIDATES) as handle:
            out.update(json.load(handle))
    out.update(private.pins())
    return out


def jar(pin_key):
    pin = pins()[pin_key]
    if pin.get('private'):
        # Bought, licensed to the owner: kept outside this repository (bench/private.py).
        return private.jar(pin_key)
    if pin.get('path'):
        # Unreleased candidate committed to this repository (own product, MIT), verified by hash.
        path = os.path.join(artifacts.ROOT, pin['path'])
        if artifacts._digest(open(path, 'rb').read(), 'sha256') != pin['sha256']:
            raise RuntimeError(f'{pin_key}: candidate JAR does not match its pinned SHA-256')
        return path
    return artifacts.fetch(dict(id=pin_key, url=pin['url'], sha512=pin['sha512'], filename=pin['filename']))


def adapter(product_id):
    with open(os.path.join(artifacts.ROOT, 'products', f'{product_id}.json')) as handle:
        return json.load(handle)
