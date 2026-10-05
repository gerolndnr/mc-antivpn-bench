# Methodology (v1)

This document is the measurement contract. It was written and committed **before** the first full run. Results that are published must say which commit of this file produced them, and any later change to a decision rule gets a new version number. A change after a result is known never silently replaces the old rule.

The bar: a developer of a competing plugin should be able to read this, rerun it and agree that their product was measured the way they would measure it themselves. Where that is impossible, the limitation is stated here rather than hidden in a number.

## 1. Conflict of interest and safeguards

The suite is written and run by the maintainers of **Connection Guard**, one of the products under test. The safeguards against that bias:

1. **Unmodified products.** Every product is the published JAR, downloaded from its official listing and checked against the listing's checksum. No product is patched, decompiled or re-implemented inside the harness.
2. **The same environment for everyone.** One container image, JDK, server build, client, set of subjects, fault model and latency model for every product, configured by data files in [`products/`](products). The harness has no product-specific code paths beyond those files.
3. **Shipped and documented configurations only.** Products run as shipped, with the single step their own documentation names to switch on blocking, or with the same two free API keys added through their own documented key fields (section 4). No hand-tuning, and every edit is listed in the adapter.
4. **Record once, serve to all.** When products send the same request to the same provider, they all get the same recorded answer (section 5). Time drift between products cannot favour anyone.
5. **No combined score.** Every question is answered separately, per cohort, with its denominator, uncertainty and raw rows. The report never ranks products on a weighted total.
6. **Everything public except volunteers' addresses.** Raw join rows, console logs and egress logs, all with subject addresses replaced by dataset ids. The adapters and this document are public too.
7. **Right of reply** (section 10). Any product author can contest an adapter, a profile or a result before or after publication. Corrections are re-measured and the original kept in the history.

## 2. Products

| Product | Version | Source | Licence |
| --- | --- | --- | --- |
| Connection Guard | 0.5.0 | [Modrinth](https://modrinth.com/plugin/connectionguard) | MIT |
| FoxGate AntiVPN (free) | 1.2.0-pre10 | [Modrinth](https://modrinth.com/plugin/foxgate) | All rights reserved |
| ProxyShield | 2.5.1 (native Paper/Folia/Velocity/Bungee builds) | [Modrinth](https://modrinth.com/plugin/proxyshield) | GPL-3.0 |
| VPNGuard | 1.2.0 | [Modrinth](https://modrinth.com/plugin/vpnguard) | All rights reserved |
| Baseline: ProxyCheck.io API | v2, `vpn=1&asn=1` | direct | service |
| Baseline: VPNAPI.io API | `/api/{ip}` | direct | service |

**Selection rule.** The newest version on Modrinth whose listed loaders include the platform under test. Where a product publishes per-platform builds, each platform gets its native build. Pins with SHA-512: [`products/modrinth-pins.json`](products/modrinth-pins.json).

**Not in v1:**
- *AntiVPN-X*: no product of that name was found on Modrinth, Hangar, SpigotMC or GitHub on 2026-10-05.
- *AdvancedAntiVPN*: commercial; it needs a licence this project does not own.

Both can be added through an adapter (section 10).

## 3. Environment

- **Image.** [`harness/docker/Dockerfile`](harness/docker/Dockerfile) on Eclipse Temurin **JDK 25** (LTS). JDK 25 is the only JDK on which every product under test loads: FoxGate 1.2.0-pre10 is compiled for class file 69 and fails on JDK 21. A JDK 21 image is built as a separate compatibility row and is not mixed into any measurement.
- **Platforms.** All are pinned with the distributor's checksum:
  - Paper 1.21.11 build 132
  - Folia 1.21.11 build 14
  - Velocity 3.5.1 build 615
  - BungeeCord build 2102 (Jenkins publishes no checksum; the SHA-256 is locked at first download)

  1.21.11 is the newest Minecraft version that **every** product declares.
- **Topologies.**
  - Paper and Folia run standalone with the PROXY protocol on.
  - Velocity and BungeeCord run with the product on the proxy and a plain Paper backend without any product (modern or legacy forwarding).
- **Client.** [`mcclient.py`](harness/bench/mcclient.py) speaks protocol 774. The subject address arrives in a PROXY protocol v2 header, so the server software, not the product, parses it. Every account name is unique, and all servers run in offline mode.
- **Fixture-wide settings.** These are applied identically to every product, because otherwise they would act before the product and mask it:
  - Paper's `connection-throttle` is set to `-1`.
  - Velocity's `login-ratelimit` is set to `0`.
  - BungeeCord's `connection_throttle` is set to `-1`.
  - bStats is off globally, because benchmarks must not inflate anyone's public statistics.
- **Hardware.**
  - Official runs use GitHub-hosted `ubuntu-latest` runners; each run records CPU model, vCPU count and memory in `manifest.json`.
  - Timings are only compared within one run on one runner.
  - Local runs serve development only.

## 4. Profiles

| Profile | Meaning | Applies to |
| --- | --- | --- |
| `shipped` | The JAR as downloaded, first start, nothing changed | clean install |
| `enforce` | `shipped` plus the **one** step the product's own documentation names to make it refuse connections. CG: `operation.mode: ENFORCE`. VPNGuard: `join-enforcement.enabled: true` (= `/vpnkick on`). FoxGate and ProxyShield block out of the box, so no step. | headline detection, false positives, failure safety, performance, Redis, platforms, reload |
| `free_keys` | `enforce` plus a free ProxyCheck key and a free VPNAPI key, set through each product's documented key fields. All four products support both. | second detection pass, secret leakage |

Profiles are data in each adapter. Section 10 explains how to contest them.

**Why "shipped" is not the headline.** Two products block nobody out of the box: CG in OBSERVE mode and VPNGuard with enforcement off. Calling that 0 % detection would measure a deliberate default, not the detection. The clean-install family still reports the as-shipped behaviour on its own.

## 5. Egress model

All outbound TCP of the product JVM is redirected by iptables to the **interposer**, an HTTP/1.1 and HTTP/2 TLS terminator with a throwaway CA. That CA is trusted only by the container's JDK.

- **Record once, serve to all.** A request is keyed by method, host, path, sorted query and auth headers, with secrets redacted and the body hashed. The first identical request is forwarded upstream; every later one, from any product, gets the recorded answer. Concurrent identical requests share one upstream call (single flight). Answers with status 429 or ≥ 500 are never recorded, so a transient provider error cannot be frozen into the dataset.
- **Downloaded lists** (Tor list, X4BNet, proxy lists) follow the same rule. Two products that use the same list see the same list content. Conditional request headers (`If-None-Match`, `If-Modified-Since`) are removed and `304` answers are never recorded, so every product always receives the full list body.
- **Telemetry, updaters and library downloads are blocked during measurement.** These are bStats, Sentry, CG Cloud, GitHub/Spigot/Modrinth/Paper version APIs and Maven repositories. Libraries are installed in the product's first start (the installed template), and FoxGate's self-updater could otherwise replace the artifact under test. After every case the harness checks that the product JAR's SHA-256 is unchanged and that no new JAR appeared.
- **Quota normalisation.**
  - *ProxyCheck:* keyless ProxyCheck allows 100 queries per day per egress address. The benchmark sends more lookups in an hour than a typical server sees in days, which would exhaust that quota through benchmark volume rather than product behaviour. For a keyless ProxyCheck request, the interposer attaches the operator's free key upstream. The product's request, cache key and the answer's schema are unchanged; this applies to every product equally.
  - *Other keyless services:* the subject pace (one subject per 5 s) keeps all products together under ip-api's 45 requests per minute.
- **Keys.** Real keys exist only in the interposer process (environment variables, never in a product JVM's environment). Product configurations hold format-compatible **canaries**. The interposer swaps a canary for the real key only toward the host that key belongs to. Everywhere else the canary stays, which is what makes leakage measurable (section 7.8).
- **Unknown egress.** Hosts that match no rule are recorded and appear in the per-case egress log. Non-HTTP egress (raw TCP) is refused and logged.

## 6. Detection dataset v1

[`datasets/detection-v1/`](datasets/detection-v1) contains 692 addresses. Ground truth comes **only** from the party that operates the address, never from a detection provider and never from agreement between providers.

| Cohort | n | Label | Ground truth | Strength |
| --- | --- | --- | --- | --- |
| `commercial_vpn` | 125 | vpn | Server lists published by Mullvad, NordVPN, PIA, IVPN and Surfshark (25 each, at most one per /24, spread over countries; NordVPN only servers older than 90 days) | operator-published |
| `fresh_vpn` | 37 | vpn | Listed by the operator today, but **absent** from the same operator's list in the newest Internet Archive capture at least 14 days old (Mullvad, PIA, IVPN); NordVPN: operator `created_at` within 30 days | operator-published, dated |
| `vpn_v6` | 40 | vpn | Mullvad's published IPv6 relay addresses | operator-published (one operator) |
| `tor` | 80 | tor | Tor Project bulk exit list | operator-published |
| `proxy` | 100 | proxy | Open proxies listed as working by ≥ 2 of 3 independently maintained, checked public lists (monosans, proxifly, vakhov) on the same day | **community-listed, weaker** |
| `residential` | 150 | non_vpn | RIPE Atlas probes tagged by their volunteer hosts as home/DSL/cable/fibre (public egress address; at most 2 per ASN) | volunteer-tagged |
| `mobile_cgnat` | 100 | non_vpn | RIPE Atlas probes on LTE/4G/5G/Starlink (carrier-grade NAT egress) | volunteer-tagged |
| `residential_v6` | 60 | non_vpn | IPv6 addresses of the residential probes | volunteer-tagged |

**Build.**
- `python3 -m bench.dataset build` is deterministic (seed `20261005`). Every raw snapshot is committed in `sources/` with its URL, fetch time and SHA-256. The RIPE Atlas input is the public daily archive for 2026-10-04.
- An address present in two cohorts is dropped from both.
- A residential probe whose address also appears in any VPN, Tor or proxy source is dropped (2 cases).

**Privacy.**
- Residential and mobile addresses belong to volunteers. They are never published; the public file carries the probe id and archive date.
- `python3 -m bench.dataset materialize` rebuilds the private file from the public RIPE Atlas archive and verifies its SHA-256 against the manifest.
- Results and logs replace every dataset address with its id.

**Label time.** VPN, Tor and proxy addresses change owners. Measurements must happen within 14 days of the build date, and the report states the gap.

**Known limitations.**
- **Entry versus exit addresses.**
  - For WireGuard on Mullvad, IVPN and PIA, the published address is the address traffic leaves from. Surfshark host names resolve to the entry address, which usually is also the exit.
  - A product that misses an address the operator does not actually use for exit would be penalised unfairly. These rows are visible per provider.
- **Proxy cohort.**
  - Community lists can be stale. Detection on this cohort is reported separately and never pooled with the VPN cohorts.
  - Two products download some of the same lists. The *circularity table* in the report shows, per product, how many cohort members appear in the lists that product downloaded.
- **Residential proxies are not measured in v1.** No free source publishes residential-proxy exits with verifiable ground truth, and a provider trial would require an account. The slot stays open for owner-verified endpoints.
- **RIPE Atlas hosts are not typical gamers.** They are technically inclined and over-represent Europe and fibre. False-positive rates describe these networks, not all players.
- **IPv6 VPN** is a single operator, so it says little about IPv6 VPN detection in general.

## 7. Test families and decision rules

Outcome classes (client-side, per join):

| Class | Meaning |
| --- | --- |
| `DENY_LOGIN` | disconnected before Login Success |
| `DENY_CONFIG` | disconnected during the configuration phase |
| `DENY_PLAY` | joined, then kicked within the 8 s observation window |
| `ALLOW` | still in the world after 8 s |
| `TIMEOUT` | no decision within the deadline |
| `ERROR` | protocol or socket failure |

`blocked` means any `DENY_*` class. *Decision time* runs from TCP connect to the disconnect (for `DENY_LOGIN`) or to Login Success.

### 7.1 Detection and false positives (Velocity)

- **Setup.** All products run at the same time behind one Velocity build, one instance each. Every subject joins all of them within the same second, in a rotating order. Subjects run in a seeded shuffle, one subject per 5 s.
- **Metrics.**
  - **Detection rate** = blocked / n for `vpn`, `tor` and `proxy` cohorts.
  - **False-positive rate** = blocked / n for `non_vpn` cohorts.
  - Each rate is reported per cohort and per product with a Wilson 95 % interval.
  - `TIMEOUT` and `ERROR` stay in the denominator (counted as not blocked for detection, not counted as a false positive) and are reported separately as *undecided*.
- **Provider-side errors.** If any provider answered 429 or ≥ 500 for a subject, that subject is re-measured once, after 90 s, on freshly started instances (so product caches cannot answer). Both attempts are kept in the raw rows. The headline uses the retry.
- **Baselines.**
  - ProxyCheck is "blocked" when `proxy == "yes"`.
  - VPNAPI is "blocked" when any of `security.vpn`, `proxy`, `tor` or `relay` is true.
  - Both are queried through the same interposer.
- **Passes.** `enforce` is the headline. `free_keys` runs only if both keys are configured.
- **Hosting addresses.** Blocking datacenter addresses is a policy choice. The dataset has no hosting cohort, so "blocks hosting" never counts as either detection or false positive.

### 7.2 Failure safety (Velocity, `enforce`)

- **Faults.** These are applied to every host in the product's `lookup_hosts`, its per-subject lookup APIs. Downloaded lists keep working, which is the realistic API outage.

  | Fault | Behaviour |
  | --- | --- |
  | `timeout` | the request is accepted and never answered |
  | `http_429` | `Retry-After: 60` |
  | `malformed` | 200 with invalid JSON |
  | `incomplete` | 200, then the connection closes mid-body |

  A `control` case without a fault runs for each product.
- **Joins.** One commercial-VPN subject, one Tor subject and one residential subject join during the fault. After the fault is cleared, the VPN subject joins again after 2 s and after 65 s, with the lookup requests of each join recorded.
- **Recorded:**
  - outcome
  - decision time
  - lookup requests per join
  - whether the process is still alive
  - product error lines
- **Pre-registered findings.** Descriptive, not a score:
  - **Hang:** decision time > 10 s, or `TIMEOUT`.
  - **Policy:** fail-open or fail-closed, compared with the product's documented policy (`documented_failure_policy` in the adapter). Neither is "wrong"; *undocumented* behaviour is the finding.
  - **Recovery delay:** the VPN subject is admitted 2 s after recovery but blocked at 65 s, although the same product blocked it in `control` (a circuit breaker or cooldown still active).
  - **Unprotected after recovery:** still admitted at 65 s. If that join made no lookup request at all, it is marked *cached*: an allow decided during the outage was stored.
  - **Retry storm:** lookup requests per join more than 3× the control.

### 7.3 Performance (Velocity, then Paper)

- **Latency model.** Lookup APIs are served from **template replay**: each product's own recorded answer for one reference residential subject, with the subject address substituted. The added latency is log-normal, median 120 ms, p95 350 ms, seeded, and identical for every product. No request leaves the container. Subjects are synthetic addresses inside the residential cohort's /24 networks.
- **Phases per round, each on a fresh instance:**

  | Phase | What happens |
  | --- | --- |
  | `cold` | 50 sequential distinct subjects |
  | `warm` | the same 50 again |
  | `stampede` | 100 simultaneous joins from **one** new address |
  | `burst` | 1,000 distinct subjects arriving open-loop at 50 per second |

- **Rounds.** 3 rounds, with the product order rotated per round. A **no-product baseline** runs in every round, so platform cost is separated from product cost.
- **Metrics.**
  - decision-time percentiles
  - outcome counts, so a burst result with errors cannot win
  - lookup requests in total and per host (coalescing and caching)
  - JVM CPU seconds and peak RSS
- **Limitations.**
  - 3 rounds on a shared CI runner support statements about large differences, not about a few milliseconds. The report shows each round, not only the median.
  - The client and servers share the host.
  - Some products' behavioural rules (e.g. ProxyShield's maximum of 4 accounts per address) legitimately refuse parts of the stampede. Those refusals are reported, not penalised.

### 7.4 Redis outage (Velocity)

- **Scope.** Only products with a documented Redis option: Connection Guard (`provider.cache.type: Redis`) and ProxyShield (`storage.type: redis`). FoxGate and VPNGuard have no Redis option and are reported as not applicable, not as failures.
- **Steps.** Each step has 2 joins, one residential and one VPN subject:
  1. Redis up
  2. Redis refusing connections
  3. Redis black-holed (packets dropped)
  4. Redis restored
  5. Product started while Redis refuses
- **Recorded:** outcomes, decision times, liveness and error lines.

### 7.5 Platforms

The `enforce` profile runs on Paper, Folia, Velocity and BungeeCord with four fixed subjects (Tor, commercial VPN, residential, mobile).

- **Loads:** no load failure in the console.
- **Parity:** the same decision as on the product's other platforms for the same subjects, which receive the same recorded answers.
- **Clean shutdown:** exit code 0, JAR unchanged.

### 7.6 Release quality

- **Clean install.** The `shipped` JAR goes into an empty plugin folder. Recorded:
  - time to ready
  - data folder created
  - product error lines
  - decisions for two subjects
- **Upgrade (Paper, Velocity).**
  1. The previous release from Modrinth starts first, and one operator value is changed (a timeout field, listed per product in [`scenarios.py`](harness/bench/scenarios.py)).
  2. The JAR is swapped and the server starts again.

  Recorded: whether the value survived, error lines and decisions.
- **Invalid config reload.**
  1. A syntactically broken YAML fragment is appended to the main config.
  2. The product's own reload command runs.
  3. A fresh Tor subject and a residential subject join; then the config is restored and reloaded once more.

  Classes:
  - **kept protection** (the fresh Tor subject still blocked, residential admitted)
  - **dropped protection**
  - **crashed**

  The run also records whether an error was visible in the console.

### 7.7 Hangs and errors in every family

The harness separates **product errors** (stack traces and ERROR lines attributed to the product by logger tag or package) from fixture errors. A fixture error makes a case *not measured*, never a product failure.

### 7.8 Secret leakage (Paper, Velocity, `free_keys`)

The run starts, three subjects join, the product's inspection commands run, then a reload and one more join. Findings:

- **`console`:** a canary appears in console or log output.
- **`file`:** a canary appears in any file other than the config file it was written into (cache databases, logs, crash reports).
- **`egress_foreign_host`:** a canary was sent to a host it does not belong to.
- **`egress_plaintext`:** a canary was sent without TLS. This is reported separately because some providers only offer HTTP on free plans.

File permissions of the configured key files are reported for information. Every product stores keys in its config file, which is normal.

## 8. What will and will not be claimed

**Will be claimed:**
- Measured rates per cohort with intervals.
- Observed behaviour under the stated fault, latency and outage models.
- Compatibility results on the pinned builds.

**Will not be claimed:**
- Detection rates "in the wild".
- Performance on other hardware.
- Behaviour of other versions.
- Ranking by any combined score.
- "Prevented attacks".
- Anything about residential proxies.

**Use in marketing.** A statement drawn from this benchmark must name the cohort, version, run and denominator, and link the report.

## 9. Reproducing a run

1. Check out the commit named in the report's `manifest.json`.
2. Run `dataset materialize`.
3. Run the family with the same image.

Pass the published `answers.sqlite` (interposer state) to replay a run's provider answers exactly. Without it, live providers answer, so detection results drift with the providers' data, by design.

## 10. Right of reply

**Contesting.** Product authors can open an issue or pull request against:
- their adapter: pins, profiles, `lookup_hosts`, readiness line, Redis edits
- the methodology
- a published result

**What happens next.**
- A contested profile is re-measured with both the original and the proposed configuration.
- Both results are published, with the product author's statement linked, before any "corrected" headline replaces the old one.

**Adding a product.** Add an adapter and the pins. The product must be publicly downloadable; a commercial product needs a licence that permits benchmarking.

The adapters for products without public source code are written from their published configuration files and observed behaviour. Their authors are invited to correct them.

## Changes before the first published run

- 2026-10-05: conditional list requests. A trial run served a recorded `304 Not Modified` to a fresh ProxyShield install without a cached copy, which disabled its list detection (fixture defect, not product behaviour). Conditional headers are now stripped and 304 answers are never recorded. Affected trial results are discarded.

- 2026-10-05: failure safety now re-joins the VPN subject at 2 s **and** 65 s after recovery. The first trial run could not tell a circuit-breaker cooldown from a cached allow; the single "poisoned cache" finding was split into *recovery delay* and *unprotected after recovery (cached)*. This change was made after seeing trial data and before any result was published.
