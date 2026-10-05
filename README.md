# mc-antivpn-bench

A reproducible benchmark for Minecraft anti-VPN plugins. It runs **unmodified, published JARs** on pinned server builds and measures three questions:

1. **Detection.** Does the product refuse VPN, proxy and Tor connections?
2. **False positives.** Does it admit residential, mobile/CGNAT and IPv6 players?
3. **Reliability.** How does it behave under provider failures, load, a Redis outage, on Paper/Folia/Velocity/BungeeCord, across install, upgrade and reload, and with API keys?

There is no combined score. Every result is reported per question, per cohort and per product, with denominators and raw data.

> **Conflict of interest.** This suite is maintained by the authors of Connection Guard, one of the products under test. The methodology, the adapters and every raw log are public, so other plugin authors can check and challenge each decision. Corrections are welcome; see [METHODOLOGY.md](METHODOLOGY.md#right-of-reply).

## What runs where

| Part | Location |
| --- | --- |
| Runtime (one image for every product, JDK 25, iptables egress guard) | [harness/docker](harness/docker/Dockerfile) |
| Minecraft 1.21.11 client (PROXY v2 subject address; login, configuration, play) | [harness/bench/mcclient.py](harness/bench/mcclient.py) |
| Egress interposer (record once and serve to all products, fault injection, canary keys) | [harness/bench/interposer.py](harness/bench/interposer.py) |
| Product adapters (pins, profiles, documented switches) | [products/](products) |
| Labelled detection dataset v1 (692 addresses, provenance per item) | [datasets/detection-v1](datasets/detection-v1) |
| Test families | [scenarios.py](harness/bench/scenarios.py), [heavy.py](harness/bench/heavy.py) |
| CI (GitHub-hosted runners) | [.github/workflows/bench.yml](.github/workflows/bench.yml) |

## Run it yourself

You need Docker on Linux, or on Docker Desktop with at least 6 GB for the VM, plus about 15 GB of disk.

```sh
docker build -t mc-antivpn-bench:dev harness/docker
docker run --rm -v "$PWD:/bench" -e PYTHONPATH=/bench/harness --entrypoint python3 mc-antivpn-bench:dev -m bench.dataset materialize
docker run --rm --cap-add NET_ADMIN -v "$PWD:/bench" -v mcbench-work:/work -e PYTHONPATH=/bench/harness \
  -e PROXYCHECK_KEY -e VPNAPI_KEY --entrypoint python3 mc-antivpn-bench:dev -m bench run functional
```

Families are `functional` (platforms, clean install, upgrade, invalid reload, secret leakage), `detection`, `failure`, `redis`, `performance` and `all`. The `contracts` CI job runs the offline tests:

```sh
PYTHONPATH=harness python3 -m unittest discover -s tests -v
```

Keys are optional. Without them the free-key profile and the VPNAPI baseline are skipped and reported as not measured. Keys reach only the interposer process: product configurations hold format-compatible canaries, which the interposer swaps for the real value only toward the provider that key belongs to.

## Licences and redistribution

This suite is MIT. It redistributes **no** product or server JAR: everything is downloaded from the official source (Modrinth, PaperMC, SpigotMC Jenkins) and verified against the published checksum ([artifacts.lock.json](artifacts.lock.json), [products/modrinth-pins.json](products/modrinth-pins.json)). Running Paper and Folia requires accepting the [Minecraft EULA](https://aka.ms/MinecraftEULA); the fixtures do this for throwaway local test servers only.
