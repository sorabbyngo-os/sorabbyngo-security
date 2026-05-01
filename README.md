<p align="center">
  <img src="https://img.shields.io/badge/standard-Kenya%20DPA%202019-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/standard-IEC%2062443-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/scanning-Trivy%20%2B%20Nuclei-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/audit-SHA--256%20chain-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square"/>
</p>

# sorabbyngo-security

> Security tooling, compliance, PKI, secrets management, audit, and incident response for the Sorabbyngo ecosystem. 7-ring defence architecture — kernel to perimeter.

## Structure
sorabbyngo-security/
├── audit/                        # Tamper-evident audit chain
│   ├── audit_writer.py           # SHA-256 chained log writer (thread-safe)
│   ├── verify_chain.py           # Chain integrity verifier
│   └── schema.json               # Audit entry JSON schema
├── compliance/
│   ├── kenya-dpa/                # Kenya DPA 2019
│   │   ├── check_compliance.py   # Automated compliance checker
│   │   ├── data_retention_policy.yaml
│   │   └── dpo_contact.yaml
│   ├── iec-62443/                # IEC 62443 industrial security
│   │   ├── check_iec62443.py     # SL2/SL3 compliance checker
│   │   └── policy.yaml
│   └── playbooks/
│       └── breach_response.md   # 72-hour ODPC breach playbook
├── docs/decisions/               # Architecture Decision Records
│   ├── ADR-001-security-architecture.md
│   ├── ADR-002-pki-architecture.md
│   ├── ADR-003-secret-rotation.md
│   └── ADR-004-audit-chain.md
├── pentest/
│   ├── scope.yaml                # Engagement scope & rules
│   ├── checklist.md              # Manual test checklist (all 7 rings)
│   ├── scripts/run_pentest.py    # Automated pentest suite
│   └── reports/                  # Test reports
├── pki/scripts/gen_certs.sh      # Root CA + service cert generation
├── policies/
│   ├── access_control.md
│   ├── password_policy.md
│   └── incident_response.md
├── scanning/
│   ├── trivy.yaml                # Vulnerability scan config
│   ├── trivy-secret.yaml         # Secret detection rules
│   └── nuclei-config.yaml        # API scan config
├── scripts/
│   ├── scan_all.sh               # Trivy + Nuclei full scan
│   ├── pre-commit-hook.sh        # Secret scanner hook
│   └── install_hooks.sh          # Deploy hook to all repos
├── secrets/scripts/
│   ├── rotate_secrets.sh         # JWT rotation
│   └── rotate_all.sh             # Full secret rotation
└── tests/
├── test_audit_writer.py
├── test_verify_chain.py
└── test_compliance.py
## Quick Start

```bash
# Run compliance checks
python3 compliance/kenya-dpa/check_compliance.py
python3 compliance/iec-62443/check_iec62443.py

# Verify audit chain integrity
python3 audit/verify_chain.py --all

# Run automated pentest (local/staging only)
python3 pentest/scripts/run_pentest.py --target novela

# Generate PKI
./pki/scripts/gen_certs.sh all

# Rotate secrets
./secrets/scripts/rotate_all.sh all

# Full vulnerability scan
./scripts/scan_all.sh

# Run tests
python3 -m pytest tests/ -v

# Install pre-commit hooks across all repos
./scripts/install_hooks.sh
```

## Compliance

| Standard | Checker | Status |
|---|---|---|
| Kenya DPA 2019 | `compliance/kenya-dpa/check_compliance.py` | Active |
| IEC 62443 SL2 | `compliance/iec-62443/check_iec62443.py` | Active |
| OWASP Top 10 | `pentest/scripts/run_pentest.py` | Active |

## CI/CD

GitHub Actions runs on every push:
- Kenya DPA 2019 compliance check
- Audit chain integrity verification
- Trivy secret + vulnerability scan
- Policy document presence check
- Security gate (blocks merge on failure)

## Related Repositories

| Repo | Ring | Role |
|---|:---:|---|
| `sorabbyngo-cyberwall` | 7 | Firewall, eBPF/XDP, YARA, malware scanner |
| `byngonet` | 6 | AI mesh, trust scoring, zone enforcement |
| `novela` | 5 | Health platform, CyberwallMiddleware |
| `cml` | 4 | AI safety, PII scrubber, prompt injection guard |
| `identity-core` | 3 | SUID, NodeID, forensic tracing |
| `sentinel-runtime` | 2 | Hash-chain audit ledger, Byngox agent |
| `sorabbyngo-os` | 1 | Kernel, SELinux, NodeID module |

---
**Sorabbyngo  ·  Kisii, Kenya  ·  2026  ·  Rhythm of Digital Life**
