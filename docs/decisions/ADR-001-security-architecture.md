# ADR-001 — Security Repository Architecture
## Status: Accepted
## Date: 2026-04-30

## Context
Sorabbyngo handles patient data under Kenya DPA 2019 and IEC 62443.
Security tooling was previously scattered or missing.

## Decision
Dedicated sorabbyngo-security repo as single source of truth for:
pentest, compliance, PKI, secrets, scanning, audit, incident response.

## Consequences
- All security work is auditable and version-controlled
- Compliance checks run in CI/CD
- Secret rotation is automated
