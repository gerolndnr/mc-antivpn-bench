"""Product artifacts and adapters (see products/*.json)."""
import json
import os

from . import artifacts

PINS = os.path.join(artifacts.ROOT, 'products', 'modrinth-pins.json')


def pins():
    with open(PINS) as handle:
        return json.load(handle)


def jar(pin_key):
    pin = pins()[pin_key]
    return artifacts.fetch(dict(id=pin_key, url=pin['url'], sha512=pin['sha512'], filename=pin['filename']))


def adapter(product_id):
    with open(os.path.join(artifacts.ROOT, 'products', f'{product_id}.json')) as handle:
        return json.load(handle)
