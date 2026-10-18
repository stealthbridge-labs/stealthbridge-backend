# Vercel Rust runtime invocation and Testnet release gate

## Observed blocker — 18 October 2026

The `stealthbridge-backend` Vercel **production** deployment and multiple READY engineering previews responded with HTTP **500**, header `x-vercel-error: INTERNAL_FUNCTION_INVOCATION_FAILED`, at `GET /health`. The new governance read `GET /v1/governance/snapshot` also failed. A minimal independent Rust `api/runtime-probe.rs` function at `GET /__runtime_probe` failed with the **same platform error**. This reproduces on a deployment preceding the governance snapshot changes. GitHub Rust/SQLx checks and Vercel compilation passed, but those do not verify function execution. Runtime log queries did not return a diagnostic error record.

**Conclusion:** the application is **not live-healthy**. Neither an exact failure cause nor a solution is verified. The evidence narrows the search toward Vercel function invocation, packaging, runtime initialization or project configuration rather than governance API business logic. Do not promote these previews or declare the product connected until direct API requests respond.

## Node.js control probe (diagnostic only)

A single **Node.js control function** is available at `GET /__runtime_node_probe`.
It does not call a backend API or touch the Stellar network, wallets, Neon or
credentials. Its success means **only** that a Node function can run within the
same Vercel project. It must never be used for deployment readiness.

Compare exactly these three routes on the same deployment:

| Route | Meaning of success | Meaning of failure |
| --- | --- | --- |
| `GET /__runtime_node_probe` | Node runtime invocation works | Project-wide function/routing problem is plausible |
| `GET /__runtime_probe` | Minimal independent Rust function can start | Rust runtime/builder/packaging needs inspection |
| `GET /health` | Axum process is responding (not ledger-ready) | Rust process/bootstrap may be down |

If Node works but both Rust endpoints fail with `INTERNAL_FUNCTION_INVOCATION_FAILED`,
escalate the Rust runtime/build artifact and region-level invocation to Vercel
with the request IDs. If all three fail, investigate deployment output and
function routing/environment before changing product code. An HTTP 200 from the
Node control **must not** cause frontend health screens, CI release gates or
operator reports to mark the backend healthy.

## Safe investigation and operator handoff

1. In Vercel, open **stealthbridge-backend → Deployments → latest production deployment → Functions / Runtime Logs**. Invoke `GET /health` and correlate the exact `x-vercel-id` request ID with the deployment. Check platform initialization failures, Rust Beta runtime settings, attached function artifacts, `api/axum.rs` rewrite destination and configured preview/production environments. Do not expose env values in issues or logs.
2. Compare `/health` with the standalone `/__runtime_probe` on the engineering preview. If both fail before function logs, collect the deployment ID, invocation timestamp, region and request ID for Vercel support. Vercel's own [function invocation failure guide](https://vercel.com/docs/errors/internal_function_invocation_failed) treats application **and** environment errors as possible causes.
3. If `/__runtime_probe` works but `/health` does not, investigate application bootstrap: `STELLAR_RPC_URL` HTTPS validation, `DATABASE_URL` secure PostgreSQL settings, auth session variable pairing and Vercel Rust Axum `VercelLayer`. The Axum adapter must return an explicit 503 on recognized configuration errors, not claim healthy.
4. Deploy a corrected **preview** and verify actual requests; only then release a reviewed change to production. Never enable payment execution or fees as a workaround for liveness.

## Acceptance: use the existing manual protected staging smoke

GitHub Actions → **Protected Testnet staging smoke** → **Run workflow** on the reviewed backend revision, with the staging environment's authorized `STEALTHBRIDGE_STAGING_API_URL` and optional Vercel bypass secret set through GitHub's secret controls. This workflow intentionally runs **only when requested**, avoiding notification spam. It calls:

```sh
python3 scripts/smoke_testnet_http.py \
  --url "https://YOUR-VERIFIED-STAGING-BACKEND" \
  --require-live-network \
  --require-governance-snapshot \
  --max-ledger-age-seconds 180
```

No secrets should be placed in the command line. The test requires: usable `/health`, fresh Testnet RPC, network/capability safety flags false, disabled settlement POST (501), an actual same-ledger three-contract governance snapshot and no false claims about fee-collection, privacy verification, signing or authorization. The script now classifies Vercel platform failures explicitly.

**Do not claim backend runtime health based solely on green CI or Vercel READY.** The staged smoke must pass with a reviewed deployment, and the new canonical release manifest, independent cryptographic verification and financial controls remain separate required milestones.
