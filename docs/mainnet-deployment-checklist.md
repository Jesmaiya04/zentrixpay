# Mainnet Readiness Checklist for the ZentrixPay Proxy

> Work through every item before pointing `STELLAR_NETWORK=mainnet` at real funds.
> The server enforces some of these checks at startup (marked **enforced**); the
> rest are operational reminders that cannot be machine-verified.

---

## 1. Network configuration

- [ ] `STELLAR_NETWORK` is set to `mainnet`.
- [ ] `NETWORK` matches the x402 mainnet network identifier (e.g. `base`).
- [ ] `SOROBAN_RPC_URL` points at a mainnet Soroban RPC node (not `testnet`).
- [ ] `FACILITATOR_URL` points at a mainnet x402 facilitator (not the testnet default).
- [ ] `USDC_CONTRACT_ID` is the **mainnet** USDC-on-Stellar SAC contract ID.
- [ ] `VAULT_REGISTRY_CONTRACT_ID` is the mainnet vault-registry contract ID.
- [ ] `REGISTRY_CONTRACT_ID` is the mainnet registry contract ID.

## 2. Key management

- [ ] `AGENT_SECRET_KEY` is a **mainnet** Stellar secret key (starts with `S`), not the testnet key.
- [ ] `REGISTRY_SECRET_KEY` is a funded mainnet deployer/owner secret key.
- [ ] **`UPSTREAM_SECRET_KEYS`** (or `UPSTREAM_SECRET_KEY`) is set; upstream API secrets
      **cannot** be stored without it.
- [ ] All secret keys are injected via a secrets manager (Vault, AWS Secrets Manager, etc.) —
      never hard-coded in environment files committed to the repository.
- [ ] Key rotation plan is in place: old key ids remain in `UPSTREAM_SECRET_KEYS` until
      all stored ciphertexts are re-encrypted with the new active key
      (`pnpm tsx server/scripts/reencrypt-secrets.ts`).

## 3. USDC contract and payment settings

- [ ] `PAY_TO` is the production platform wallet address, verified on-chain.
- [ ] `VERIFICATION_PRICE` is reviewed and set to the correct USD amount for mainnet traffic.
- [ ] Per-API `price` values are confirmed in USDC (not test amounts).

## 4. SSRF and upstream safety **(enforced)**

- [ ] `PROXY_ALLOW_PRIVATE_UPSTREAMS` is **not** set to `true` in any mainnet deployment.
      The server will **refuse to start** if this is misconfigured on mainnet.
- [ ] Outbound IP allowlisting is in place at the network layer as a defence-in-depth measure.

## 5. Rate limits and resource caps

- [ ] `RATE_LIMIT_VERIFY_IP_MAX` and wallet-based limits are sized for expected mainnet traffic.
- [ ] `PROXY_MAX_RESPONSE_BYTES` and per-API `maxResponseBytes` are reviewed.
- [ ] `PROXY_MAX_REQUEST_BODY` is appropriate (default 5 MB).

## 6. Database and infrastructure

- [ ] `DATABASE_URL` points at a production Postgres instance with daily backups.
- [ ] `SUPABASE_URL` and `SUPABASE_SERVICE_KEY` are production credentials.
- [ ] Supabase storage bucket (`SUPABASE_STORAGE_BUCKET`) is a production bucket with
      access policies set.
- [ ] Drizzle migrations have been run against the production database
      (`pnpm --filter @zentrixpay/server db:migrate`).

## 7. Observability

- [ ] `SENTRY_DSN` is set so unhandled errors are captured.
- [ ] `METRICS_TOKEN` is set and the `/metrics` endpoint is not publicly reachable.
- [ ] Structured logs are shipped to a log aggregation service.
- [ ] Alerting is configured for: payment failures, upstream errors (5xx rate), DB pool exhaustion.

## 8. TLS and secrets scanning

- [ ] The server is behind a TLS-terminating reverse proxy or load balancer.
- [ ] `BASE_URL` uses `https://`.
- [ ] `WEB_APP_URL` uses `https://`.
- [ ] Secret scanning (gitleaks) passes on the final commit: `make secrets-scan`.

## 9. Final smoke test

- [ ] `pnpm --filter @zentrixpay/server test:e2e:mainnet` passes (or the equivalent
      mainnet smoke script).
- [ ] A manual curl confirms a live paid call through the proxy settles correctly.
- [ ] `GET /.well-known/x402` returns the expected discovery index.

---

_Last updated: 2026-10_ — update this file whenever deployment requirements change.
