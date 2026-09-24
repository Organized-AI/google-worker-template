# google-worker-template

A deployable Cloudflare Worker that holds **N Google accounts across unrelated domains** behind one API and dashboard. Starting point for any Google API integration — Gmail, Drive, GA4, Ads, Tag Manager, Sheets, whatever.

Companion to the `organized-google-wiring` plugin, which carries the framework, the API catalogue, and the failure-mode log.

## What you get out of the box

Encrypted token vault (AES-GCM, per-account HKDF keys, rotation-safe refresh), PKCE + single-use DB-verified OAuth state, account registry with health, fan-out engine with partial-success `207` semantics and KV-backed rate limiting, dry-run-by-default write guards, Google sign-in with owner/operator/viewer roles and per-account allowlists, an audit log attributing every action to a user, scheduled sweeps over cron → queue with resumable cursors, and a dark-theme GSAP dashboard on Worker Assets.

## Quick start

```bash
git clone https://github.com/organized-ai/google-worker-template my-worker && cd my-worker
# rename: set "name" in wrangler.jsonc (lowercase, dashes) — everything else keys off it
# 1. provision (GCP project, APIs, D1, KV, schema, secrets)
./scripts/gcp-provision.sh my-worker my-gcp-project gmail drive
# 2. paste the printed ids into wrangler.jsonc, then
wrangler deploy
# 3. confirm /health is green with only the two Google secrets missing
# 4. create the OAuth client in the Console (this part cannot be automated)
# 5. ./scripts/set-google-secrets.sh ~/Downloads/client_secret_*.json
```

## Sweeps are opt-in

The Worker deploys and runs with no queues. To enable scheduled sweeps, create the two queues (`wrangler queues create <name>-sweeps` and `<name>-sweeps-dlq`), then uncomment the `queues` and `triggers` blocks in `wrangler.jsonc`. Until then, firing a sweep returns a clear 503 instead of a TypeError.

## Adapting it to a different Google API

Edit `src/config.ts` — capability-to-scope map and any extra headers. Replace the adapters in `src/google.ts` with calls to your API. Everything else is API-agnostic.

Google Ads needs a `developer-token` header on every call in addition to the bearer; without it you get 401/403 forever.

## Before you connect anything real

**Publish the OAuth app to In Production.** In Testing status, refresh tokens expire seven days after consent and every connected account dies at once, silently.

## Design rules worth keeping

No mutating route defaults to all accounts. No send route infers its from-address. One account failing never fails a fan-out. Refresh tokens never leave the Worker. Audit rows are written before execution, not after.

---

Guide: [guide.organizedai.vip/synter-gap-plan/](https://guide.organizedai.vip/synter-gap-plan/)

Maintained by Jordaaan Hill ([LinkedIn](https://www.linkedin.com/in/jordaaanhill)).
