# Prepaid API call credits

This document describes the implementation design: x402-paid bundle purchases,
a per-API/per-wallet balance and append-only ledger, and Stellar wallet-signed
request authentication for spends.

Credits are scoped to one API and one Stellar wallet. A credit represents one
call to that API, regardless of the endpoint's per-call price rule. To keep a
bundle valid for every configured endpoint, its x402 purchase price is the
highest configured per-call price (including the API default) multiplied by
the requested number of calls.

## Purchase, balance, and spend

- `POST /apis/:id/credits/purchase` accepts `{"calls": 1000}` and is protected
  by x402. The payment goes to the API's configured payout wallet. On
  settlement, the caller receives the requested credits in that API's ledger.
- `GET /apis/:id/credits/balance?walletAddress=G...` returns the wallet's
  current balance for that API.
- A call to `/api/:id/*` spends one credit instead of requiring a per-call
  x402 payment when it includes all four headers:
  `X-Credit-Wallet`, `X-Credit-Timestamp`, `X-Credit-Nonce`, and
  `X-Credit-Signature`.

The signature is a base64 Stellar Ed25519 signature over this exact UTF-8
message, with newline separators and no trailing newline:

```text
zentrixpay:api-credit-spend
<wallet-address>
<api-id>
<uppercase-method>
<original request path and query>
<unix timestamp in seconds>
<unique nonce>
<lowercase hex SHA-256 of the raw request body>
```

For an empty body, hash the empty byte string. The request path is the
origin-form path and query exactly as sent (for example,
`/api/weather/v1/forecast?units=metric`). Nonces must be 16–128 characters
from `A-Z`, `a-z`, `0-9`, `.`, `_`, `~`, and `-`; timestamps must be within
the configured signature clock-skew window. A caller can sign the message
with its Stellar account key; the API never asks for or stores that key.

Credit balances and ledger entries are updated in one PostgreSQL transaction.
Spends are accepted only when an atomic conditional balance decrement succeeds.
The ledger enforces a unique `(API, wallet, nonce)` spend, so retries cannot
spend the same signed request twice; concurrent distinct requests cannot reduce
the balance below zero. Purchase references are unique to prevent a settled
payment being credited more than once.
