# sorabbyngo-security

> Security tooling, compliance, PKI, secrets management, and incident response for the Sorabbyngo Labs ecosystem.

## Structure
sorabbyngo-security/
├── compliance/kenya-dpa/     # Kenya DPA 2019 compliance checker
├── compliance/playbooks/     # Incident response playbooks
├── pki/scripts/              # TLS cert generation
├── secrets/scripts/          # Secret rotation
├── scanning/                 # Trivy + Nuclei configs
├── audit/                    # Audit log schemas
├── policies/                 # Security policies
└── docs/decisions/           # ADRs
## Quick Start

```bash
python3 compliance/kenya-dpa/check_compliance.py
./pki/scripts/gen_certs.sh all
./secrets/scripts/rotate_secrets.sh status
./scripts/scan_all.sh
```

## Compliance
- Kenya Data Protection Act 2019
- IEC 62443 (medical devices — Novela OS)
- OWASP Top 10 (Labs APIs)
