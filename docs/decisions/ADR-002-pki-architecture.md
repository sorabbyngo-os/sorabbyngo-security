# ADR-002 — PKI Architecture

## Status: Accepted
## Date: 2026-04-30

## Context
All Sorabbyngo services communicate over mTLS. A PKI is required to issue, renew, and revoke service certificates. Kenya DPA 2019 Section 41 and IEC 62443 FR4 require encryption in transit.

## Decision
Single-root CA (Sorabbyngo Root CA) with per-service leaf certificates.

- Root CA: 4096-bit RSA, 10-year validity, offline storage
- Service certs: 2048-bit RSA, 365-day validity, auto-renewed via `gen_certs.sh`
- Services: novela, karibu, dawa, pulse, taifa, dashboard, cyberwall, nats, byngonet
- CA key stored with dual-control access (DPO + CTO)

## Consequences
- All service-to-service traffic is mutually authenticated
- Certificate compromise requires immediate re-issuance via `pki/scripts/gen_certs.sh all`
- Root CA rotation is a major operation requiring planned downtime
