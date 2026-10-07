# Provider keys

Two free keys enable the `free_keys` profile, the VPNAPI baseline and quota normalisation for keyless ProxyCheck (METHODOLOGY 5). Without them, those parts are reported as *not measured*.

| Secret | Where | Free tier |
| --- | --- | --- |
| `PROXYCHECK_KEY` | <https://proxycheck.io/dashboard/> | 1,000 queries per day |
| `VPNAPI_KEY` | <https://vpnapi.io/dashboard> | 1,000 queries per day |

Create the accounts yourself, then add the keys as repository secrets: *Settings → Secrets and variables → Actions → New repository secret*. Alternatively, run in your own terminal:

```sh
gh secret set PROXYCHECK_KEY -R gerolndnr/mc-antivpn-bench
gh secret set VPNAPI_KEY -R gerolndnr/mc-antivpn-bench
```

`gh` asks for the value interactively, so it never lands in your shell history.

**A second ProxyCheck key (optional).** The nightly keyed detection chunks use `PROXYCHECK_KEY`, and one free key allows 1,000 queries a day. A manual run started with `use_keys` uses `PROXYCHECK_KEY_2` instead when it is set, so it never spends the nightly quota:

```sh
gh secret set PROXYCHECK_KEY_2 -R gerolndnr/mc-antivpn-bench
```

Without it, a manual `use_keys` run falls back to `PROXYCHECK_KEY`.

The `providers` family (METHODOLOGY 7.9) also measures services that only answer with a free key. Each is optional; a service without its key is skipped and listed as such:

| Secret | Where | Free tier |
| --- | --- | --- |
| `PROVIDER_KEY_IPAPI_IS` | <https://ipapi.is/> | 1,000 queries per day, commercial use allowed |
| `PROVIDER_KEY_IPLOCATE` | <https://www.iplocate.io/> | 1,000 queries per day |
| `PROVIDER_KEY_IP2LOCATION` | <https://www.ip2location.io/> | 50,000 per month; open proxies only on free plans |
| `PROVIDER_KEY_IPHUB` | <https://iphub.info/> | 1,000 queries per day |

`VPNAPI_KEY` is reused. In this family keys go straight to their own service, not through the interposer; they appear in no result file.

For local runs, put the keys in `.env` (git-ignored) and pass `--env-file .env` to `docker run`.

The keys are passed only to the interposer process. Product configurations receive canaries, and logs and results redact both the canary and the real value. A full detection pass uses about 692 queries per provider.

## Private artifacts (`ARTIFACT_KEY`)

Every run uploads `results-public` in the clear. Three artifacts can contain volunteers' addresses and are encrypted before upload: `results-private` (unmasked results), `interposer-logs` (egress log) and `interposer-state` (recorded provider answers, reused with `state_from_run`). Without the `ARTIFACT_KEY` secret they are not uploaded at all.

Create the secret once in your own terminal. The value is generated and never printed:

```sh
openssl rand -base64 48 | tr -d '\n' > ~/.mc-antivpn-bench-artifact-key && chmod 600 ~/.mc-antivpn-bench-artifact-key
gh secret set ARTIFACT_KEY -R gerolndnr/mc-antivpn-bench < ~/.mc-antivpn-bench-artifact-key
```

To read one locally:

```sh
gh run download <run-id> -R gerolndnr/mc-antivpn-bench -n results-private -D private-<run-id>
openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass file:$HOME/.mc-antivpn-bench-artifact-key \
  -in private-<run-id>/results-private.tgz.enc | tar xzf - -C private-<run-id>
```

## Bought products (`PRIVATE_PLUGINS_TOKEN`)

AdvancedAntiVPN is a paid SpigotMC plugin. Its JAR carries the buyer's SpigotMC id, so it is kept in the private repository `gerolndnr/mc-antivpn-bench-private`, release `plugins`:

| File | Content |
| --- | --- |
| `AdvancedAntiVPN-2.31.8.jar` | the JAR as downloaded from SpigotMC |
| `private.json` | `{"sha256": {"<file>": "<hex>"}, "redact": ["<buyer id>", "<nonce>", ...]}` |

CI downloads that release into `cache/private/plugins/` with a read-only token. The folder is git-ignored and not in the Actions cache. Public results are masked with the `redact` values and are withheld if one remains (`bench/private.py`). Without the secret, bought products are left out.

The token is a fine-grained personal access token:
- **Repository access:** only `mc-antivpn-bench-private`.
- **Permissions:** *Contents: Read-only*.
- **Expiry:** at most a year.

Create it at <https://github.com/settings/personal-access-tokens/new>, then run:

```sh
gh secret set PRIVATE_PLUGINS_TOKEN -R gerolndnr/mc-antivpn-bench
```

For local runs, put the two files into `cache/private/plugins/` yourself.

A new version means a new JAR and new `redact` values: upload both to the same release.
