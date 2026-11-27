# Anti-VPN plugins, measured.

*Published run · 22–27 November 2026 · Velocity*

6 unmodified plugins on the same server, with the same players and the same simulated detection services.

The same numbers as the [overview graphic](overview-dark.png), redrawn after each run. Bold marks the best value in each row.

## Stress test: 1,000 players join in 20 seconds

*Velocity · median of 3 rounds* · Players checked, by a detection service or the plugin's own list. Unchecked players got in without an answer or were cut off. Higher is better. Cut off: closed by the proxy after 30 s.

| Plugin | Result | Detail |
| --- | ---: | --- |
| Connection Guard v0.6.1 | **1,000 of 1,000** | decided within 451 ms |
| FoxGate 1.2.0-pre12 | **1,000 of 1,000** | decided within 976 ms |
| ProxyShield 3.1.0 | 735 of 1,000 | decided within 1.7 s · 265 unchecked · fast admit off (shipped: skips home networks in waves) |
| VPNGuard 1.2.0 | 47 of 1,000 | decided within 11.1 s · 953 unchecked |
| KauriVPN 1.10.1.1 | after join | lets everyone in, kicks later |
| AdvancedAntiVPN 2.31.8 | 500 of 1,000 | decided within 27 s · 500 unchecked · 525 cut off |

## Everyday joins

Same simulated services, same delays and free-tier limits for every plugin.

|   | Connection Guard v0.6.1 | FoxGate 1.2.0-pre12 | ProxyShield 3.1.0 | VPNGuard 1.2.0 | KauriVPN 1.10.1.1 | AdvancedAntiVPN 2.31.8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Single join, p95 | 289 ms | 634 ms | 953 ms | **287 ms** | after join | 420 ms |
| Repeat join, p50 | 2.1 ms | 303 ms | **1.5 ms** | **1.5 ms** | after join | 3.3 ms |
| Lookups, 100 same-IP joins | **1** | 6 | 2 | **1** | 2 | 300 |
| Players checked in the stress test | **1,000** | **1,000** | 735 | 47 | 631 | 500 |
| Start-up | 6.5 s | 8.3 s | 17.2 s | **6.3 s** | **6.3 s** | 7.1 s |

## Load limit: joins a second until checks fail

*Velocity · 1 round* · Rising join rates, 10 s each, fresh players, 60 s rest; then halving to within 5/s. A rate works when 99 % get a decision, 99 % are checked and p95 stays under 5 s. Higher is better.

| Plugin | Result | Detail |
| --- | ---: | --- |
| Connection Guard v0.6.1 | 29/s | breaks at 37/s: 22 of 370 unchecked |
| ProxyShield 3.1.0 | **58/s** | breaks at 62/s: 14 of 620 unchecked · fast admit off (shipped: skips home networks in waves) |
| VPNGuard 1.2.0 | < 3/s | at 3/s: 30 of 30 unchecked, p95 10 s |
| KauriVPN 1.10.1.1 | 15/s | breaks at 18/s: 14 of 180 unchecked · checks after the join |
| AdvancedAntiVPN 2.31.8 | 6/s | breaks at 9/s: p95 7.3 s |
| *Test machine without a plugin* | 124/s | the most joins a second this runner sends |

## Detection and false positives

697 real addresses, as shipped, no API keys. Each number: addresses blocked.

|   | Connection Guard v0.6.1 | FoxGate 1.2.0-pre12 | ProxyShield 3.1.0 | VPNGuard 1.2.0 | KauriVPN 1.10.1.1 | AdvancedAntiVPN 2.31.8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ***Should be blocked · higher is better*** | | | | | | |
| Commercial VPNs (125) | **125** | **125** | **125** | 124 | 123 | 43 |
| Newly added VPN servers (45) | **45** | **45** | **45** | 40 | **45** | 15 |
| VPNs over IPv6 (40) | **40** | **40** | **40** | 34 | 4 | 16 |
| Tor exits (80) | **80** | **80** | **80** | 75 | 76 | 25 |
| Public proxies (100) | 98 | **100** | **100** | 86 | 64 | 29 |
| **Blocked of 390** | 388 | **390** | **390** | 359 | 312 | 128 |
| ***Should get in · fewer refused is better*** | | | | | | |
| Home connections (148) | **0** | 1 | 3 | 2 | 3 | 0 |
| Home connections, IPv6 (60) | **0** | 1 | **0** | 1 | 1 | 0 |
| Mobile networks (98) | **0** | 1 | 1 | 1 | 4 | 0 |
| **Refused of 306** | **0** | 3 | 4 | 4 | 8 | 0 |
| ***Rates*** | | | | | | |
| True flags · bad addresses blocked | 99.5 % | **100.0 %** | **100.0 %** | 92.1 % | 80.0 % | 32.8 % |
| False flags · good players refused | **0.0 %** | 1.0 % | 1.3 % | 1.3 % | 2.6 % | 0.0 % |
| ***Not graded · blocking these is a policy choice*** | | | | | | |
| Not an access network (tunnel, hosting, campus) (1) | 0 blocked | 0 blocked | 0 blocked | 0 blocked | 0 blocked | 0 blocked |

> Connection Guard v0.6.1, FoxGate 1.2.0-pre12, ProxyShield 3.1.0, VPNGuard 1.2.0, AdvancedAntiVPN 2.31.8 ask ProxyCheck without a key, as shipped. ProxyCheck answers 100 such lookups a day per server; each plugin ran on a server of its own, and after its 100 ProxyCheck answered it no more, as on a busy real server.  
> Not counted: 1 contested address whose label was shown not to hold when measured (datasets/contested.json, with the evidence).  
> KauriVPN 1.10.1.1 lets every player in and checks afterwards: its blocks are kicks of a player who is already on the server. Its join times are therefore shown as "after join".  

## Detection, best configuration with free keys

715 real addresses, each plugin's best configuration, free keys included. Each number: addresses blocked.

|   | Connection Guard v0.6.1 | FoxGate 1.2.0-pre12 | VPNGuard 1.2.0 | KauriVPN 1.10.1.1 | AdvancedAntiVPN 2.31.8 |
| --- | ---: | ---: | ---: | ---: | ---: |
| ***Should be blocked · higher is better*** | | | | | |
| Commercial VPNs (125) | **125** | **125** | **125** | 123 | **125** |
| Newly added VPN servers (45) | **45** | **45** | 43 | **45** | **45** |
| VPNs over IPv6 (40) | **40** | **40** | 38 | 4 | **40** |
| Tor exits (83) | **83** | **83** | 77 | 81 | **83** |
| Public proxies (115) | 110 | **115** | 111 | 86 | 113 |
| **Blocked of 408** | 403 | **408** | 394 | 339 | 406 |
| ***Should get in · fewer refused is better*** | | | | | |
| Home connections (148) | **0** | **0** | **0** | 3 | **0** |
| Home connections, IPv6 (60) | **0** | 1 | **0** | 1 | **0** |
| Mobile networks (98) | 1 | 1 | **0** | 4 | **0** |
| **Refused of 306** | 1 | 2 | **0** | 8 | **0** |
| ***Rates*** | | | | | |
| True flags · bad addresses blocked | 98.8 % | **100.0 %** | 96.6 % | 83.1 % | 99.5 % |
| False flags · good players refused | 0.3 % | 0.7 % | **0.0 %** | 2.6 % | **0.0 %** |
| ***Not graded · blocking these is a policy choice*** | | | | | |
| Not an access network (tunnel, hosting, campus) (1) | 0 blocked | 0 blocked | 0 blocked | 0 blocked | 0 blocked |

> Not counted: 1 contested address whose label was shown not to hold when measured (datasets/contested.json, with the evidence).  
> KauriVPN 1.10.1.1 lets every player in and checks afterwards: its blocks are kicks of a player who is already on the server. Its join times are therefore shown as "after join".  

## When detection services fail

VPN and Tor still refused while every service fails this way.

|   | Connection Guard v0.6.1 | FoxGate 1.2.0-pre12 | ProxyShield 3.1.0 | VPNGuard 1.2.0 | KauriVPN 1.10.1.1 | AdvancedAntiVPN 2.31.8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Services healthy | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Services time out | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Rate limited (429) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Broken answers | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Cut-off answers | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **Home login while timing out** | 4.5 s | **2.3 s** | 6.5 s | 5 s | after join | 3 s |

## Redis outage

Correct decisions in under 10 s while the shared cache is down.

|   | Connection Guard v0.6.1 | FoxGate 1.2.0-pre12 | ProxyShield 3.1.0 | VPNGuard 1.2.0 | KauriVPN 1.10.1.1 | AdvancedAntiVPN 2.31.8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Up | ✅ | no Redis | ✅ | no Redis | no Redis | no Redis |
| Refused | ✅ | no Redis | ✅ | no Redis | no Redis | no Redis |
| Black-holed | ✅ | no Redis | ✅ | no Redis | no Redis | no Redis |
| Restored | ✅ | no Redis | ✅ | no Redis | no Redis | no Redis |
| Start while down | ✅ | no Redis | ✅ | no Redis | no Redis | no Redis |
| – not measured in this run |  |  |  |  |  |  |

## Platforms and release quality

Fixed VPN, Tor, home and mobile joins on every platform; counts are platforms passed.

|   | Connection Guard v0.6.1 | FoxGate 1.2.0-pre12 | ProxyShield 3.1.0 | VPNGuard 1.2.0 | KauriVPN 1.10.1.1 | AdvancedAntiVPN 2.31.8 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Paper | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Folia | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| Velocity | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| BungeeCord | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Installs cleanly | ✅ (4/4) | ✅ (4/4) | ✅ (4/4) | ❌ (3/4) | ❌ (3/4) | ❌ (3/4) |
| Blocks VPN and Tor out of the box | ✅ (4/4) | ✅ (4/4) | ✅ (4/4) | ❌ (0/4) | ❌ (3/4) | ❌ (0/4) |
| Upgrade keeps the operator's settings | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | – |
| Broken config reload stays protected | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | ❌ (1/2) | ✅ (2/2) | ❌ (1/2) |
| API keys never leak | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) | ✅ (2/2) |

## Detection services on their own

*694 addresses* · Score = 100 × (share caught − 3 × share refused) − 5 per second of median time. Each service at its own quota; hosting alone is not a hit. Flag rates of all addresses; unanswered counts as not flagged.

| Service | Score | VPN, Tor, proxies caught | True flags | Home and mobile refused | False flags | Answered | Median time | Access |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| zowi | **99.4** | **386/386** | **100.0 %** | **0/308** | **0.0 %** | 694/694 | 126 ms | keyless |
| ipapi.is | 97.8 | 384/386 | 99.5 % | 1/308 | 0.3 % | 694/694 | 135 ms | key |
| Connection Guard Intel (own, see note) | 97.7 | 377/386 | 97.7 % | **0/308** | **0.0 %** | 694/694 | **< 0.1 ms** | **local lists, no quota** |
| ProxyCheck | 94.6 | 374/386 | 96.9 % | 1/308 | 0.3 % | 694/694 | 273 ms | key |
| IPQuery | 92.1 | 359/386 | 93.0 % | **0/308** | **0.0 %** | 694/694 | 186 ms | keyless |
| ip-check.net | 88.5 | 369/386 | 95.6 % | 6/308 | 1.9 % | 694/694 | 258 ms | keyless |
| Blackbox | 88.1 | 365/386 | 94.6 % | 6/308 | 1.9 % | 694/694 | 121 ms | keyless |
| VPNAPI | 88.0 | 350/386 | 90.7 % | 2/308 | 0.6 % | 694/694 | 139 ms | key |
| IPLocate | 84.4 | 327/386 | 84.7 % | **0/308** | **0.0 %** | 694/694 | 58 ms | key |
| PaperStream Intel | 81.7 | 324/386 | 83.9 % | **0/308** | **0.0 %** | 694/694 | 452 ms | keyless |
| IP-API | 80.0 | 309/386 | 80.1 % | **0/308** | **0.0 %** | 694/694 | 18 ms | keyless |
| IPHub | 76.6 | 305/386 | 79.0 % | **0/308** | **0.0 %** | 594/694 | 481 ms | key |
| funkemunky (KauriVPN) | 75.8 | 323/386 | 83.7 % | 6/308 | 1.9 % | 691/694 | 414 ms | keyless |
| marvinmc.dev | 74.8 | 306/386 | 79.3 % | 2/308 | 0.6 % | 594/694 | 505 ms | keyless |
| GetIPIntel | 70.0 | 274/386 | 71.0 % | **0/308** | **0.0 %** | 499/694 | 189 ms | key |
| IP2Location.io | 24.0 | 95/386 | 24.6 % | 0/308 | 0.0 % | 694/694 | 118 ms | keyless |
| iprisk.info | 23.0 | 93/386 | 24.1 % | 0/308 | 0.0 % | 594/694 | 226 ms | keyless |
| FreeIPAPI | 0.0 | 0/386 | 0.0 % | 0/308 | 0.0 % | 694/694 | 245 ms | keyless |
| IPHunter | 0.0 | 0/386 | – | 0/308 | – | 0/694 | – | key |
| Negativity | 0.0 | 0/386 | 0.0 % | 0/308 | 0.0 % | 594/694 | 770 ms | keyless |
| rayzs.de | 0.0 | 0/386 | 0.0 % | 0/308 | 0.0 % | 694/694 | 329 ms | keyless |

> Not counted: 30 Tor exits and 18 public proxies of the dataset that had left the Tor exit list or the proxy list by the start of a run shown here.  
> Own: Connection Guard Intel is the benchmark author's project. Its VPN and Tor lists come from the same sources that label those addresses, so those numbers show coverage; its proxy list uses none of the proxy cohort's sources.  

---

Method, raw data and every log: github.com/gerolndnr/mc-antivpn-bench · runs 45067206486, 45067209616, 45067212229, 45067215075, 45067217627, 45068357470, 45068359877, 45068362397, 45068364289, 45131639606, 45368660226, 45508280763, 45575298463, 45780247468, 45806957069, 45964371515, 45964374609, 45964377849, 45964380759, 45964383595, 45964386570, 45964392669 · commit 1ddbb66  
Bold marks the best value in each row. Results describe this setup and dataset, not every server.  
Conflict of interest: maintained by the author of Connection Guard.  
Other plugin authors can contest adapters and results (METHODOLOGY 10).  
