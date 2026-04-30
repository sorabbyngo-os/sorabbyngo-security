# Password & Credential Policy
**Sorabbyngo Labs · v1.0 · 2026-04-30 · Kenya DPA 2019 Section 41 | OWASP ASVS L2**

## Password Requirements
| Parameter | Requirement |
|---|---|
| Minimum length | 12 characters |
| Complexity | Upper + lower + digit + symbol |
| Maximum age | 90 days (admin/security: 60 days) |
| History | Last 12 passwords blocked |
| Breach check | HaveIBeenPwned on set |

## Account Lockout
- 5 failed attempts → 15-min lockout
- 10 failed attempts → locked, manual DPO unlock
- All lockouts logged to sentinel with SUID + IP

## Secret Management
All secrets must: live in env vars or secrets manager (never source code), be ≥64 chars, be rotated on schedule, never appear in logs.

## Rotation Schedule
| Secret | Period | Script |
|---|---|---|
| JWT_SECRET | 90 days | `secrets/scripts/rotate_secrets.sh jwt` |
| DB passwords | 180 days | `secrets/scripts/rotate_secrets.sh db` |
| TLS certs | 365 days | `pki/scripts/gen_certs.sh all` |
| Root CA | 10 years | Manual — dual control |
| NATS creds | 90 days | `secrets/scripts/rotate_secrets.sh nats` |
| Anthropic API key | On compromise | Immediate |

## MFA — Mandatory For
- All admin accounts
- DPO access
- Security operations
- Bulk patient data access

Accepted: TOTP only (no SMS).

## Developer Workstations
- SSH keys: 4096-bit RSA or Ed25519 + passphrase
- `.env` never committed — enforced via `.gitignore`
- Trivy pre-commit hook required on all repos

---
*Review: Quarterly | Owner: DPO | Last reviewed: 2026-04-30*
