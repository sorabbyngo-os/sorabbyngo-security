# ADR-004 — Tamper-Evident Audit Chain

## Status: Accepted
## Date: 2026-04-30

## Context
Kenya DPA 2019 Section 41 requires audit logs to be maintained and protected. IEC 62443 FR3 requires integrity verification.

## Decision
SHA-256 hash-chained JSONL audit log:

- Each entry contains `sha256_prev` (hash of previous entry) and `sha256_self` (hash of this entry excluding sha256_self)
- Genesis entry uses `sha256_prev = "0" * 64`
- Append-only — no entry can be modified without breaking the chain
- Verified by `audit/verify_chain.py --all`
- Written by `audit/audit_writer.py` — thread-safe, used by all components

## Chain integrity check
Run in CI on every push. Any break triggers immediate DPO notification.

## Consequences
- Log deletion is detectable (chain break)
- Log modification is detectable (hash mismatch)
- Log reordering is detectable (prev hash mismatch)
- Storage: `/var/log/sorabbyngo/audit.jsonl` (prod) or `audit/logs/audit.jsonl` (dev)
