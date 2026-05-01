# ADR-003 — Secret Rotation Strategy

## Status: Accepted
## Date: 2026-04-30

## Context
JWT secrets, DB passwords, and API keys must be rotated regularly per Kenya DPA 2019 Section 41 and the password policy.

## Decision
Automated rotation via `secrets/scripts/rotate_all.sh`:

| Secret | Period | Method |
|---|---|---|
| JWT_SECRET | 90 days | `rotate_all.sh jwt` — sed replace in .env |
| CHECKSUM_SECRET | 90 days | `rotate_all.sh checksum` |
| DB passwords | 180 days | Manual + `rotate_all.sh db` (planned) |
| TLS certs | 365 days | `pki/scripts/gen_certs.sh all` |
| Anthropic API key | On compromise | Manual — immediate |

## Consequences
- JWT rotation invalidates all active sessions — schedule during low-traffic window
- Secrets never committed to git — enforced by pre-commit hook
- All rotations logged to sentinel audit ledger
