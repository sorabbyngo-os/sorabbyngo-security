# Sorabbyngo Labs — Data Breach Response Playbook
# Kenya DPA 2019 — Section 43 (72-hour ODPC notification)

## Hour 0-1: Contain
- [ ] Identify affected service and data category
- [ ] Isolate: `docker-compose stop <service>`
- [ ] Preserve logs: `cp -r /var/log/sorabbyngo/ /secure/incident-$(date +%Y%m%d)/`
- [ ] Notify DPO: security@sorabbyngo.co.ke

## Hour 1-4: Assess
- [ ] Scope — how many records affected?
- [ ] Root cause (CVE, misconfiguration, insider)
- [ ] Run cyberwall forensics

## Hour 4-72: Notify ODPC (MANDATORY)
Submit to: complaints@odpc.go.ke

Subject: Data Breach Notification — Sorabbyngo Labs — [DATE]
- Nature of breach
- Categories of data affected
- Number of records/subjects
- Measures taken

## Contacts
| Role | Contact |
|------|---------|
| DPO | security@sorabbyngo.co.ke |
| ODPC | complaints@odpc.go.ke |
