# Access Control Policy
**Sorabbyngo Labs · v1.0 · 2026-04-30 · Kenya DPA 2019 Section 25**

## Principle of Least Privilege
Every user, service, and component gets only the minimum permissions required. No exceptions without DPO approval.

## Roles
| Role | Systems | Permitted Actions |
|---|---|---|
| `patient` | portal-patient | Read own records, book appointments |
| `chw` | portal-chw | Read assigned patients, submit vitals |
| `clinician` | portal-clinical | Read/write patient records, prescribe |
| `pharmacist` | portal-pharmacy | Dispense, verify prescriptions |
| `lab_tech` | portal-lab | Submit lab results |
| `admin` | All portals | User management — no patient data |
| `insurer` | portal-insurer | Anonymised aggregate data only |
| `system` | Internal | Service-to-service via NodeID + mTLS |
| `security_ops` | security, sentinel | Audit logs, threat response |
| `dpo` | All (read-only) | Compliance audit, no modification |

## Authentication
- Patients/CHWs/Clinicians: JWT (24h) + NodeID header
- Admins: JWT + TOTP (2FA mandatory)
- Service-to-service: mTLS + Sorabbyngo Root CA + NodeID
- Security Ops: SSH key only (passwords disabled)

## Session Management
- JWT expires 24h — no exceptions
- Inactive sessions terminated after 30 minutes
- All session events logged to sentinel audit ledger

## Privileged Access
- No shared accounts — every actor has unique SUID
- `root` on production: DPO approval + dual control required
- Privileged sessions recorded + logged
- Access reviewed quarterly

## Violations
Access violations → immediate suspension → DPO notified within 1h → ODPC if personal data accessed (Section 43)

---
*Review: Quarterly | Owner: DPO | Last reviewed: 2026-04-30*
