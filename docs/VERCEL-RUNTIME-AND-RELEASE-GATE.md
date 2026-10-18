# Vercel Rust runtime invocation and Testnet release gate

## Observed blocker — 18 October 2026

The `stealthbridge-backend` Vercel **production** deployment and multiple READY engineering previews responded with HTTP **500**, header `x-vercel-error: INTERNAL_FUNCTION_INVOCATION_FAILED`, at `GET /health`. The new governance read `GET /v1/governance/snapshot` also failed. A minimal independent Rust `api/runtime-probe.rs` function at `GET /__runtime_probe` failed with the **same platform error**. This reproduces on a deployment preceding the governance snapshot changes. GitHub Rust/SQLx checks and Vercel compilation passed, but those do not verify function execution. Runtime log queries did not return a diagnostic error record.

**Conclusion:** the application is **not live-healthy**. Neither an exact failure cause nor a solution is verified. The evidence narrows the search toward Vercel function invocation, packaging, runtime initialization or project configuration rather than governance API business logic. Do not promote these previews or declare the product connected until direct API requests respond.

## Reproduced Vercel-native Rust invocation failure — 18 October 2026

The existing production deployment and **two fresh preview deployments built from backend `main` with build cache explicitly bypassed** were tested. A minimal Node function in the same project returns JSON with HTTP 200, but both `api/runtime-probe.rs` and `api/axum.rs` return HTTP 500 with `x-vercel-error: INTERNAL_FUNCTION_INVOCATION_FAILED`, even on `/health`. This precedes any network or database interaction in the minimal Rust probe. No Rust application errors were returned from the Vercel observability API.

Tested without resolution:

- Aligning Rust handler binary name with `api/axum.rs`.
- Forcing a clean Vercel build by creating new preview deployments with `forceNew=1`. The logs confirm `Skipping build cache, deployment was triggered without cache`.
- Enabling Fluid Compute at the Vercel backend project level and rebuilding without cache.
- Comparing Vercel Node control with the independent Rust runtime probe and full Axum route on **the same deployed URL**.

**Reproducing deployment:** `dpl_G7in9kWLk2Sc9LnHkTY9SQayZqTq` (preview built from `main`). Node `/__runtime_node_probe`: 200; Rust `/__runtime_probe`: 500; `/health`: 500. Sample failed request IDs from the same deployment: `fra1:iad1::stbx5-1792338537746-f9e645d3bc55`, `fra1:iad1::dzr5t-1792338606115-c4d6a5d0d1d7`. They contain no access credentials. The exact Rust execution failure remains **unidentified**; do not claim the backend is fixed.

**Follow-up:** Open that deployment's **Resources → Rust function artifact / runtime settings / Logs** in Vercel and verify actual binary packaging, architecture, permissions, shared library loading, runtime bridge initialization, invocation region and Beta runtime service errors. Escalate the minimal independent Rust repro and request IDs to Vercel support if no invocation traces exist. Preserve SSO protection and read-only financial gates. An HTTP 200 on Node must never satisfy backend release acceptance.

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
