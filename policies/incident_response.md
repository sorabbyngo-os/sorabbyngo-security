# Incident Response Policy
**Sorabbyngo Labs · v1.0 · 2026-04-30 · Kenya DPA 2019 Section 43**

## Classification
| Severity | Description | SLA |
|---|---|---|
| P1 CRITICAL | Patient data breach, system-wide compromise | 15 min |
| P2 HIGH | Partial breach, service outage | 1 hour |
| P3 MEDIUM | Attempted breach, policy violation | 4 hours |
| P4 LOW | Anomaly, advisory | 24 hours |

## Response Team
| Role | Contact |
|---|---|
| Incident Commander | CTO |
| DPO | security@sorabbyngo.co.ke |
| Security Ops | On-call engineer |

## Phases

**Phase 1 — Detect:** Sentinel → `sorabbyngo.sentinel.threat` → Byngox evaluates → escalates if score ≥ 7

**Phase 2 — Contain (0–1h):**
- [ ] Identify affected service + data category
- [ ] Isolate: `docker-compose stop <service>`
- [ ] Preserve logs: `cp -r /var/log/sorabbyngo/ /secure/incident-$(date +%Y%m%d)/`
- [ ] Revoke compromised credentials
- [ ] Notify Incident Commander

**Phase 3 — Assess (1–4h):**
- [ ] Scope — records/nodes affected
- [ ] Root cause (CVE, misconfig, insider)
- [ ] `./scripts/scan_all.sh`
- [ ] `python3 audit/verify_chain.py --all`

**Phase 4 — Notify ODPC (≤72h) — MANDATORY if personal data accessed:**
Send to: complaints@odpc.go.ke — Nature of breach, categories affected, count, measures taken.

**Phase 5 — Eradicate:**
- [ ] Patch vulnerable component
- [ ] `./secrets/scripts/rotate_secrets.sh all`
- [ ] `./pki/scripts/gen_certs.sh all` (if PKI compromised)
- [ ] `python3 compliance/kenya-dpa/check_compliance.py`

**Phase 6 — Recover:** Restore from clean backup, gradual restoration, monitor 30 days.

**Phase 7 — Post-Incident Review (≤2 weeks):** RCA doc + timeline + ADR if architecture changed.

## Evidence Preservation
Minimum 3 years (Kenya DPA 2019 Section 41): raw logs, network captures, timeline, all communications.

---
*Review: Annually or after any P1/P2 | Owner: DPO | Last reviewed: 2026-04-30*
