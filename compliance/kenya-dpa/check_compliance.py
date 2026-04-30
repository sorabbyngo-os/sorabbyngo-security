#!/usr/bin/env python3
"""
Sorabbyngo Labs — Kenya DPA 2019 Compliance Checker
"""
import json, os, sys, yaml
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RESET="\033[0m"; RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"; BOLD="\033[1m"
SCRIPT_DIR=Path(__file__).parent; REPO_ROOT=SCRIPT_DIR.parent.parent

@dataclass
class CheckResult:
    name: str; passed: bool; message: str; section: str; severity: str = "HIGH"

@dataclass
class ComplianceReport:
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    results: list = field(default_factory=list)
    score: int = 0; total: int = 0
    def add(self, r):
        self.results.append(r); self.total += 1
        if r.passed: self.score += 1
    @property
    def percentage(self): return (self.score/self.total*100) if self.total else 0.0

def check_dpo_appointed(report):
    f = SCRIPT_DIR/"dpo_contact.yaml"
    if not f.exists(): report.add(CheckResult("DPO Appointed",False,"dpo_contact.yaml missing","Section 24")); return
    data=yaml.safe_load(f.read_text()); appointed=data.get("dpo",{}).get("appointed_date")
    report.add(CheckResult("DPO Appointed",appointed is not None,f"Appointed: {appointed}" if appointed else "appointed_date is null","Section 24"))

def check_retention_policy(report):
    f = SCRIPT_DIR/"data_retention_policy.yaml"
    if not f.exists(): report.add(CheckResult("Retention Policy Exists",False,"missing","Section 39")); return
    data=yaml.safe_load(f.read_text()); periods=data.get("retention_periods",{})
    report.add(CheckResult("Retention Policy Exists",len(periods)>0,f"{len(periods)} categories defined","Section 39"))
    years=periods.get("patient_records",{}).get("retention_years",0)
    report.add(CheckResult("Patient Record Retention ≤10yr",years<=10,f"Set to {years} years","Section 39"))

def check_breach_notification(report):
    f = SCRIPT_DIR/"data_retention_policy.yaml"
    if not f.exists(): report.add(CheckResult("Breach Notification Config",False,"missing","Section 43")); return
    data=yaml.safe_load(f.read_text()); deadline=data.get("breach_notification",{}).get("odpc_deadline_hours",0)
    report.add(CheckResult("72-hour ODPC Notification",deadline<=72,f"Deadline: {deadline}h","Section 43"))
    playbook=REPO_ROOT/"compliance"/"playbooks"/"breach_response.md"
    report.add(CheckResult("Breach Response Playbook",playbook.exists(),"found" if playbook.exists() else "missing","Section 43"))

def check_encryption_at_rest(report):
    f = SCRIPT_DIR/"data_retention_policy.yaml"
    if not f.exists(): report.add(CheckResult("Encryption At Rest",False,"missing","Section 41")); return
    data=yaml.safe_load(f.read_text()); periods=data.get("retention_periods",{})
    issues=[c for c,cfg in periods.items() if cfg.get("storage","") and "encrypted" not in cfg.get("storage","").lower() and "memory" not in cfg.get("storage","").lower()]
    report.add(CheckResult("Encryption At Rest Documented",len(issues)==0,"All documented" if not issues else f"Missing: {issues}","Section 41"))

def check_pki(report):
    s=REPO_ROOT/"pki"/"scripts"/"gen_certs.sh"
    report.add(CheckResult("PKI Script Exists",s.exists(),"found" if s.exists() else "missing","Section 41"))
    ca=(REPO_ROOT/"pki"/"ca"/"ca.crt").exists()
    report.add(CheckResult("Root CA Generated",ca,"ca.crt found" if ca else "Run: ./pki/scripts/gen_certs.sh all","Section 41","MEDIUM"))

def check_secret_rotation(report):
    s=REPO_ROOT/"secrets"/"scripts"/"rotate_secrets.sh"
    report.add(CheckResult("Secret Rotation Script",s.exists(),"found" if s.exists() else "missing","Section 41"))

def check_audit_logging(report):
    report.add(CheckResult("Audit Log Dir",(REPO_ROOT/"audit"/"logs").exists(),"found","Section 41"))
    report.add(CheckResult("Audit Schema",(REPO_ROOT/"audit"/"schema.json").exists(),"found" if (REPO_ROOT/"audit"/"schema.json").exists() else "missing","Section 41","MEDIUM"))
    report.add(CheckResult("Audit Chain Verifier",(REPO_ROOT/"audit"/"verify_chain.py").exists(),"found" if (REPO_ROOT/"audit"/"verify_chain.py").exists() else "missing","Section 41","MEDIUM"))

def check_vulnerability_scanning(report):
    report.add(CheckResult("Scan Script",(REPO_ROOT/"scripts"/"scan_all.sh").exists(),"found","Section 41"))
    report.add(CheckResult("Trivy Config",(REPO_ROOT/"scanning"/"trivy.yaml").exists(),"found" if (REPO_ROOT/"scanning"/"trivy.yaml").exists() else "missing","Section 41","MEDIUM"))

def check_policies(report):
    for p in ["access_control.md","password_policy.md","incident_response.md"]:
        f=REPO_ROOT/"policies"/p
        report.add(CheckResult(f"Policy: {p}",f.exists(),"found" if f.exists() else "missing","Section 25","MEDIUM"))

def run_checks():
    report=ComplianceReport()
    for fn in [check_dpo_appointed,check_retention_policy,check_breach_notification,check_encryption_at_rest,check_pki,check_secret_rotation,check_audit_logging,check_vulnerability_scanning,check_policies]:
        try: fn(report)
        except Exception as e: report.add(CheckResult(fn.__name__,False,f"Error: {e}","N/A"))
    return report

def print_report(report):
    print(f"\n{BOLD}{CYAN}{'─'*60}{RESET}")
    print(f"{BOLD}{CYAN}  Sorabbyngo Labs — Kenya DPA 2019 Compliance{RESET}")
    print(f"{CYAN}  {report.timestamp}{RESET}")
    print(f"{CYAN}{'─'*60}{RESET}\n")
    for r in report.results:
        icon=f"{GREEN}✓{RESET}" if r.passed else f"{RED}✗{RESET}"
        sev=f" {YELLOW}[{r.severity}]{RESET}" if not r.passed else ""
        print(f"  {icon}  {r.name:<45}{sev}")
        if not r.passed: print(f"      {YELLOW}↳ {r.message}  ({r.section}){RESET}")
    c=GREEN if report.percentage>=80 else YELLOW if report.percentage>=60 else RED
    print(f"\n{BOLD}{c}{'─'*60}")
    print(f"  Score: {report.score}/{report.total}  ({report.percentage:.0f}%)")
    print(f"  {'COMPLIANT ✓' if report.percentage==100 else 'MOSTLY COMPLIANT — fix HIGH items' if report.percentage>=80 else 'NON-COMPLIANT — action required'}")
    print(f"{'─'*60}{RESET}\n")

def save_json(report):
    out=REPO_ROOT/"audit"/"logs"; out.mkdir(parents=True,exist_ok=True)
    f=out/f"compliance-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.json"
    f.write_text(json.dumps({"timestamp":report.timestamp,"score":report.score,"total":report.total,"percentage":report.percentage,"results":[{"name":r.name,"passed":r.passed,"message":r.message,"section":r.section,"severity":r.severity}for r in report.results]},indent=2))
    print(f"  Saved: {f.relative_to(REPO_ROOT)}\n")

if __name__=="__main__":
    r=run_checks(); print_report(r); save_json(r); sys.exit(0 if r.percentage==100 else 1)
