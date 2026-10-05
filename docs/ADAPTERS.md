# Product adapters

Each product is described by one JSON file in [`products/`](../products). The harness has no product-specific code. If your product is measured wrongly, the fix belongs in your adapter, and you are invited to send it.

| Field | Meaning |
| --- | --- |
| `pins` | Modrinth pin per platform (see `products/modrinth-pins.json`, produced by `python3 -m bench pins`). The newest version whose loaders include the platform; native per-platform builds where they exist. |
| `previous_pins` | The release before, used by the upgrade test. |
| `data_dir` | Plugin data folder name per platform. |
| `ready_pattern` | A console line that means "fully initialised" (lists loaded, services ready). Without one, readiness is 5 s without new console output or egress. **If your product finishes loading after the server's "Done", set this.** |
| `profiles.enforce` | The **single** documented step to make the product refuse connections. Empty if it blocks out of the box. Cite the documentation in `note`. |
| `profiles.free_keys` | Where the free ProxyCheck and VPNAPI keys go. `{canary:proxycheck}` and `{canary:vpnapi}` are replaced by format-compatible fake keys; the interposer swaps them for real keys toward the owning host only. |
| `redis` | Edits that switch the product to Redis, or `null` with `redis_note` if the product has no Redis option. |
| `commands.reload`, `commands.inspect` | Console commands used by the reload and secret-leakage tests. |
| `lookup_hosts` | Hosts the product queries **per subject**. The failure-safety test faults exactly these, and the performance test replays them with the latency model. Lists downloaded at start-up must not be listed here. |
| `list_sources` | Lists the shipped configuration downloads; used only for the circularity table. |
| `documented_failure_policy` | What your documentation says happens when providers fail. The failure test compares behaviour with this. |

Edits address YAML paths that must already exist in the generated configuration; a missing path aborts the case. The harness never invents keys.

## Proposing a change

1. Open a pull request that changes your adapter, with a link to your documentation for any profile change.
2. CI runs the offline contracts. A maintainer then runs the affected families with both the old and the new adapter.
3. Both results are published side by side with your statement before a corrected headline replaces the old one (METHODOLOGY section 10).

## Adding a product

The product must be publicly downloadable; a commercial product needs a licence that permits benchmarking. Steps:

1. Add the pin to `MATRIX` in [`pins.py`](../harness/bench/pins.py).
2. Run `python3 -m bench.discover 1.1.1.1 <pin>@paper <pin>@velocity` in the container. Discovery prints which files the product creates, which hosts it contacts and how it decides.
3. Write the adapter from that evidence and from the product's own documentation.
