"""Product artifacts and adapters (see products/*.json)."""
import json
import hashlib
import re
from pathlib import Path
import os

from . import artifacts

PINS = os.path.join(artifacts.ROOT, 'products', 'modrinth-pins.json')


def pins():
    with open(PINS) as handle:
        published = json.load(handle)
    candidate_file = Path(artifacts.ROOT) / "products/candidate-pins.json"
    candidates = json.loads(candidate_file.read_text()) if candidate_file.exists() else {}
    if set(candidates) & set(published):
        raise ValueError("Candidate pins must never replace a published pin")
    for key, pin in candidates.items():
        if not key.startswith("connectionguard-candidate-") or pin.get("release_status") != "unreleased" or not re.fullmatch("[a-f0-9]{40}", pin.get("source_commit", "")):
            raise ValueError("Invalid experimental candidate provenance")
    return {**published, **candidates}


def jar(pin_key):
    pin = pins()[pin_key]
    if pin.get('release_status') == 'unreleased':
        expected = pin['sha256']
        if not re.fullmatch('[a-f0-9]{64}', expected) or pin['artifact'] != f'cache/candidates/{expected}.jar':
            raise ValueError('Candidate must be staged by its content hash inside the ignored cache')
        path = Path(artifacts.ROOT) / pin['artifact']
        if not path.is_file():
            raise RuntimeError(f'{pin_key}: stage the unpublished JAR from the pinned source commit; no candidate is downloaded automatically')
        data = path.read_bytes()
        if len(data) != pin['size'] or hashlib.sha256(data).hexdigest() != expected or hashlib.sha512(data).hexdigest() != pin['sha512']:
            raise RuntimeError('Experimental candidate checksum mismatch')
        return str(path)
    return artifacts.fetch(dict(id=pin_key, url=pin['url'], sha512=pin['sha512'], filename=pin['filename']))


def adapter(product_id):
    with open(os.path.join(artifacts.ROOT, 'products', f'{product_id}.json')) as handle:
        return json.load(handle)
