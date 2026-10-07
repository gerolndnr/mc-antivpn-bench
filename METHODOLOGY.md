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
| Connection Guard | 0.6.0 (c4b67eb) and 0.5.1 | [Modrinth](https://modrinth.com/plugin/connectionguard) | MIT |
| FoxGate AntiVPN (free) | 1.2.0-pre10 | [Modrinth](https://modrinth.com/plugin/foxgate) | All rights reserved |
| ProxyShield | 2.5.1 (native Paper/Folia/Velocity/Bungee builds) | [Modrinth](https://modrinth.com/plugin/proxyshield) | GPL-3.0 |
| VPNGuard | 1.2.0 | [Modrinth](https://modrinth.com/plugin/vpnguard) | All rights reserved |
| KauriVPN (Kauri AntiVPN) | 1.10.1.1; 1.10.1.2 on Folia (published for Folia only) | [Modrinth](https://modrinth.com/plugin/kauri-antivpn) | Apache-2.0 |
| AdvancedAntiVPN | 2.31.8 (one JAR for Spigot/Paper, BungeeCord and Velocity) | [SpigotMC](https://www.spigotmc.org/resources/101081/), paid, bought | Commercial |
| Baseline: ProxyCheck.io API | v2, `vpn=1&asn=1` | direct | service |
| Baseline: VPNAPI.io API | `/api/{ip}` | direct | service |

**Selection rule.** The newest version on Modrinth whose listed loaders include the platform under test. Where a product publishes per-platform builds, each platform gets its native build. Pins with SHA-512: [`products/modrinth-pins.json`](products/modrinth-pins.json).

**Bought products.** AdvancedAntiVPN is sold only on SpigotMC. The benchmark owner bought it at the listed price, like any server owner; its author did not provide it.
- Every SpigotMC premium download carries its buyer's id, which AdvancedAntiVPN prints at startup and sends in its licence check. So the JAR, its hash and that id are kept in a private repository, not here.
- CI downloads it only into the git-ignored cache. The public pin ([`products/private-pins.json`](products/private-pins.json)) names the version only.
- Public logs show the buyer id as `<purchaser>`. A run whose public results still contain it uploads none ([`harness/bench/private.py`](harness/bench/private.py)).
- Without the owner's copy the product is left out, so others cannot reproduce this row without buying it themselves.

**Not in v1:**
- *AntiVPN-X*: no product of that name was found on Modrinth, Hangar, SpigotMC or GitHub on 2026-10-05.
- *v4Guard*: the connector checks nothing until the server is linked to a v4Guard account in its web dashboard ("This instance is not connected to a company! We're not processing your checks."), every fresh instance gets a new link code, all settings live in that dashboard, and the connector talks to its service over a WebSocket (Socket.IO) that the interposer can neither record nor fault. Checked 7 October 2026.

Either can be added through an adapter (section 10).

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
| `proxycheck_key` | `enforce` plus the free ProxyCheck key only, set through each product's documented key field (all four support it) | detection quality per decision |
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
- **Two questions, two passes.**
  - **Capacity of the shipped configuration (`enforce`).** Some products limit their own keyless lookups per day (Connection Guard: 100 ProxyCheck queries, counted locally). When that limit ends lookups, the product admits unchecked. The `enforce` pass reports when that happened, as the subject index from which no lookup was made, and the detection rates over all subjects, which then mix both effects.
  - **Detection quality per decision (`proxycheck_key`).** This is the headline for detection and false positives: every product gets the same free ProxyCheck key, so no product runs out of lookups during the 692 subjects.
  - `free_keys` adds VPNAPI and runs only if both keys are configured.
  - **Quota-safe chunks.** All products share one free ProxyCheck key (1,000 queries per day) and query it in different formats, about 5 queries per subject. The `proxycheck_key` pass therefore runs in 4 nightly chunks (stable hash of the subject id, cohorts mixed), each after the key's daily reset. Within a subject every product is still measured in the same second; across chunks, provider data may drift by up to 3 days, which the report states.
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

- **Profiles.** `enforce` and `free_keys` are run as separate passes. Keyless defaults can carry a product-enforced daily quota (CG counts ProxyCheck's 100 keyless queries per day locally), which ends lookups during a long test. Under template replay no request reaches a real provider, so `free_keys` removes that confound without spending quota.
- **Provider quotas.** Template replay enforces each provider's published free-tier limit (ip-api 45/min, ProxyCheck 1,000/day with key, VPNAPI 1,000/day, ipapi.is 1,000/day, freeipapi 60/min; list in `heavy.PROVIDER_QUOTAS` with sources) and answers 429 above it, as the real service would. Providers without a published limit are not limited, and the report names them. Without this, a product that fans out to many keyless services would appear to scale without limit in replay.
- **Latency model.** Lookup APIs are served from **template replay**: each product's own recorded answer for one reference residential subject, with the subject address substituted. The added latency is log-normal, median 120 ms, p95 350 ms, seeded, and identical for every product. No request leaves the container. Subjects are synthetic addresses in the /12 networks around residential cohort addresses, never inside a volunteer's own /24. Published logs mask every address that is not a dataset id.
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
  - **subjects checked:** distinct burst subjects for which at least one lookup request was made. A product that admits players *without* checking them is fast for the wrong reason; this column makes that visible.
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

### 7.9 Detection services on their own (`providers`)

No plugin and no server: the harness sends every dataset address straight to each detection service and reads the answer the way the plugins do. This measures the data source, separately from any plugin's use of it.

- **Fair use.** One request per second per service (1.5 s for IP-API, whose free limit is 45 a minute), an identifying User-Agent, the service's own daily quota as a hard stop. A `429` is retried once after 60 s. Keys are used only where configured (`docs/KEYS.md`); the shared `PROXYCHECK_KEY` is not used by this family, so its quota stays with the nightly detection chunks.
- **Order.** Cohorts are interleaved in a seeded order (seed `20261007`) in proportion to their size. A service whose quota is smaller than the dataset therefore answers a sample with every cohort in it. The unanswered rest is `not_queried`.
- **Reading an answer.**
  - `positive`: any explicit VPN, proxy or Tor flag.
  - `negative`: all of them explicitly false.
  - `unknown`: hosting alone, or flags missing. Hosting is review evidence, never a positive, as in the plugins.
  - Errors (`rate_limited`, `http_<code>`, `timeout`, `unreadable`, `not_queried`) are reported per service.
- **Metrics per service.** Caught = `positive` / all VPN, Tor and proxy addresses. Refused = `positive` / all home and mobile addresses. Both have Wilson 95 % intervals; an unanswered address counts as neither caught nor refused. Latency p50 and p95 of answered lookups. Answers per cohort, including the hosting flag.
- **Chains.** The answers are replayed through lookup chains: Connection Guard 0.6's shipped order (`intel, proxycheck, blackbox, zowi, ipquery, ip-api`), the same with Blackbox needing confirmation, without IP-API, and with every other keyless service in IP-API's place or directly after Blackbox.
  - The first `positive` or `negative` decides. `unknown` and errors pass to the next service.
  - `intel` checks Connection Guard Intel's published lists, fetched at the end of the run, with their `as_of` recorded: VPN and Tor decide, hosting is evidence only.
  - Each chain runs twice: with one day's quota for every service, and with services whose daily quota is below the dataset size *used up*, as on a busy server.
  - A replay is not a plugin measurement: it leaves out caching, timeouts and concurrency, which the other families measure.
- **Terms.** Each service's terms as checked on 7 October 2026 are printed next to its numbers. A good result does not make a service suitable as a default; the report says when terms are missing or restrict commercial use.
- **Connection Guard Intel** is measured as a service too (`cg-intel`): its published lists, checked locally like a plugin does, with no lookup and no quota. VPN, Tor or proxy list → `positive`; relay → `negative`; hosting alone or no list → `unknown`. The lists are fetched once at the end of the run, with their `as_of` recorded.
- **Conflict of interest.** Connection Guard's author wrote this family, and Connection Guard Intel comes from the same author; it is marked as such in every table. Its VPN and Tor lists are built from the same operator lists and Tor list that label the VPN and Tor cohorts (6, circularity), so those rows show coverage, not how well it finds unknown servers. Its proxy list uses none of the three lists the proxy cohort was built from.

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

## Corrections and changes after the first published run

- **2026-10-07, FoxGate adapter: `api.zowi.gay` was missing from `lookup_hosts`.** FoxGate asks it once per player address. Connection Guard's adapter listed the same host; FoxGate's did not.
  - *Performance* (run 37540317765): FoxGate's zowi lookups went to the live service instead of the simulated one, about 1,000 synthetic addresses at 50 a second, while every other service ran at the simulated latency. FoxGate's performance numbers of that run are not comparable.
  - *Failure* (run 37540309049): the host was not faulted, so FoxGate kept one working service.
  - *Detection*: outcomes are unaffected (every lookup is live there); its lookup counts left zowi out.
  - Found while checking a question from FoxGate's author about `central.zowi.gay/tors`, which was fetched normally (HTTP 200).
  - Fixed in the adapter. Both families now stop with an error when a product asks an unlisted host about a subject (docs/ADAPTERS.md). Re-run: failure 37593590733, performance 37593586654. In the failure re-run FoxGate refused the VPN subject in all five fault cases.
- **2026-10-07, KauriVPN added** (Modrinth, Apache-2.0). It enforces out of the box and asks only its author's own service (funkemunky.cc, 20,000 free queries); it has no ProxyCheck or VPNAPI key fields, so `proxycheck_key` and `free_keys` measure it as `enforce`. The keyed detection chunks of 7-10 October keep the five products they started with; KauriVPN joins the next keyed series.
- **2026-10-07, AdvancedAntiVPN added** (SpigotMC, paid, bought at the listed price; see "Bought products" in section 2).
  - As shipped every service is off, so it blocks nobody.
  - `enforce` switches on the three services its config offers without a key (IP-API, ProxyCheck, VPNAPI) and keeps the default vote of 2.
  - Folia is not advertised; the Folia row records whether it loads.
- **2026-10-07, KauriVPN on Folia:** 1.10.1.2 throws while enabling (it schedules with the Bukkit scheduler, which Folia refuses) and then admits everyone. The platform check now counts "Error occurred while enabling" as a load failure; before, it only looked for "Could not load plugin".
  - It joins the next keyed detection series, like KauriVPN.
- **2026-10-07, family `providers`** (7.9): every detection service on its own, Connection Guard Intel among them (marked as the author's project), and replays of lookup chains, including the planned Connection Guard 0.6.1 chain.
- **2026-10-07, overview graphic** at the end of every run and at the top of the README: the newest complete result of every family, the newest pinned version of each plugin, the accent on the best value of each row.

## Changes before the first published run

- **2026-10-07, published run for Connection Guard 0.6.0.** Candidate c4b67eb (JAR sha256 8ba9534a…c2b2) against stable 0.5.1 (previously 0.5.0) and the current FoxGate, ProxyShield and VPNGuard releases. The keyed detection profile runs in four nightly chunks from 7 to 10 October 2026, one per UTC day, so one free ProxyCheck key covers every product.
- **2026-10-06, private CI artifacts encrypted.** Before the repository went public, unmasked results, egress logs and recorded provider answers were uploaded as plain workflow artifacts. They are now encrypted with a repository secret (docs/KEYS.md), and the earlier ones were deleted.
- **2026-10-06, performance templates for failover chains.** A product that asks its services one after another only asks a fallback when the services before it fail, so the single reference join recorded the first service only and every fallback request in template replay got "no recorded answer". The reference is now recorded on a throwaway instance once normally and once per still unrecorded lookup host with the other hosts answering 503; each host replays its own reference answer. Products that ask all services at once are unaffected. Burst results of failover products measured before this change are not valid.
- 2026-10-05: performance template replay now emulates published provider quotas (429 above the free limit). The first trial burst replayed unlimited answers for every product except Connection Guard, which enforces its own quota mirror, so the comparison was unequal.

- 2026-10-05: detection gets a `proxycheck_key` headline pass. The first full `enforce` pass showed Connection Guard's shipped 100/day keyless ProxyCheck budget ending lookups after subject ~100 (logged `BUDGET_EXHAUSTED`, then fail-open). That is reported as a capacity finding of the shipped configuration and kept separate from detection quality. Every product receives the same key through its own documented field.

- 2026-10-05: performance adds the *subjects checked* metric and a `free_keys` pass, after the first Velocity trial showed CG's local keyless ProxyCheck budget ending lookups mid-burst. Synthetic subjects no longer come from volunteers' /24 networks, and published logs mask all non-dataset addresses.

- 2026-10-05: conditional list requests. A trial run served a recorded `304 Not Modified` to a fresh ProxyShield install without a cached copy, which disabled its list detection (fixture defect, not product behaviour). Conditional headers are now stripped and 304 answers are never recorded. Affected trial results are discarded.

- 2026-10-05: failure safety now re-joins the VPN subject at 2 s **and** 65 s after recovery. The first trial run could not tell a circuit-breaker cooldown from a cached allow; the single "poisoned cache" finding was split into *recovery delay* and *unprotected after recovery (cached)*. This change was made after seeing trial data and before any result was published.
