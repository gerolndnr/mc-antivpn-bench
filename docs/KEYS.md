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

For local runs, put the keys in `.env` (git-ignored) and pass `--env-file .env` to `docker run`.

The keys are passed only to the interposer process. Product configurations receive canaries, and logs and results redact both the canary and the real value. A full detection pass uses about 692 queries per provider.
