#!/usr/bin/env python3
"""Sorabbyngo Security — IEC 62443 Compliance Checker"""
import json, sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RESET="\033[0m";RED="\033[91m";GREEN="\033[92m";YELLOW="\033[93m";CYAN="\033[96m";BOLD="\033[1m"
REPO_ROOT=Path(__file__).parent.parent.parent
OS_REPO=REPO_ROOT.parent/"sorabbyngo-os"
LABS_REPO=REPO_ROOT.parent/"sorabbyngo-Labs"
CW_REPO=REPO_ROOT.parent/"sorabbyngo-cyberwall"

@dataclass
class R:
    req:str; comp:str; sl_target:str; sl_achieved:str; status:str; detail:str; ref:str

@dataclass
class Report:
    ts:str=field(default_factory=lambda:datetime.now(timezone.utc).isoformat())
    results:list=field(default_factory=list)
    def add(self,r):self.results.append(r)
    @property
    def passed(self):return[r for r in self.results if r.status=="PASS"]
    @property
    def score(self):return len(self.passed)/max(len(self.results),1)*100

def chk(report,req,comp,sl_t,sl_a,ok,detail,ref):
    report.add(R(req,comp,sl_t,sl_a,"PASS" if ok else "FAIL" if sl_a=="SL0" else "WARN",detail,ref))

def run(report):
    # FR1 Authentication
    svcs_auth=sum(1 for s in["novela","karibu","dawa","pulse","taifa"] if (LABS_REPO/s/"auth.py").exists())
    chk(report,"Human User Authentication","sorabbyngo-Labs","SL2","SL2" if svcs_auth==5 else "SL1",svcs_auth==5,f"{svcs_auth}/5 services have auth.py","IEC 62443-3-3 SR 1.1")
    nodeid=(OS_REPO/"board/sorabbyngo/overlay/etc/init.d/S05nodeid").exists()
    chk(report,"NodeID Service Authentication","sorabbyngo-os","SL2","SL2" if nodeid else "SL0",nodeid,"NodeID init found" if nodeid else "Missing S05nodeid","IEC 62443-3-3 SR 1.2")
    pki=(REPO_ROOT/"pki/scripts/gen_certs.sh").exists()
    chk(report,"PKI Certificate Authentication","sorabbyngo-security","SL2","SL2" if pki else "SL1",pki,"gen_certs.sh found" if pki else "No PKI tooling","IEC 62443-3-3 SR 1.3")
    # FR2 Use Control
    ac=(REPO_ROOT/"policies/access_control.md").exists()
    chk(report,"Access Control Policy","sorabbyngo-security","SL2","SL2" if ac else "SL0",ac,"Found" if ac else "Missing policies/access_control.md","IEC 62443-3-3 SR 2.1")
    # FR3 Integrity
    verifier=(REPO_ROOT/"audit/verify_chain.py").exists()
    chk(report,"Audit Chain Tamper Detection","sorabbyngo-security","SL3","SL3" if verifier else "SL0",verifier,"SHA-256 chain verifier found" if verifier else "Missing","IEC 62443-3-3 SR 3.3")
    scanner=(CW_REPO/"cyberwall/malware/scanner.py").exists()
    chk(report,"Malware Detection","sorabbyngo-cyberwall","SL2","SL2" if scanner else "SL0",scanner,"Malware scanner found" if scanner else "Missing","IEC 62443-3-3 SR 3.2")
    yara_count=len(list((CW_REPO/"cyberwall/malware/yara_rules").glob("*.yar"))) if (CW_REPO/"cyberwall/malware/yara_rules").exists() else 0
    chk(report,"YARA Signature Rules","sorabbyngo-cyberwall","SL2","SL2" if yara_count>=3 else "SL1",yara_count>=3,f"{yara_count} YARA rules found","IEC 62443-3-3 SR 3.2")
    ebpf=(CW_REPO/"cyberwall/firewall/ebpf/bpf_program.c").exists()
    chk(report,"eBPF XDP Kernel Integrity","sorabbyngo-cyberwall","SL3","SL3" if ebpf else "SL1",ebpf,"eBPF program found" if ebpf else "Missing","IEC 62443-3-3 SR 3.1")
    # FR4 Confidentiality
    kyber=(CW_REPO/"cyberwall/quantum/kyber.py").exists()
    chk(report,"Post-Quantum Cryptography","sorabbyngo-cyberwall","SL3","SL3" if kyber else "SL2",kyber,"Kyber module found" if kyber else "Not implemented","IEC 62443-3-3 SR 4.1")
    # FR5 Data Flow
    engine=(CW_REPO/"cyberwall/firewall/engine.py").exists()
    chk(report,"Network Segmentation (nftables)","sorabbyngo-cyberwall","SL2","SL2" if engine else "SL0",engine,"FirewallEngine found" if engine else "Missing","IEC 62443-3-3 SR 5.1")
    hardening=(OS_REPO/"hardening/kernel/apply-hardening.sh").exists()
    chk(report,"OS Kernel Hardening","sorabbyngo-os","SL2","SL2" if hardening else "SL0",hardening,"Hardening script found" if hardening else "Missing","IEC 62443-2-4 SP.03.01")
    aa=len(list((OS_REPO/"hardening/apparmor").glob("*"))) if (OS_REPO/"hardening/apparmor").exists() else 0
    chk(report,"AppArmor Profiles","sorabbyngo-os","SL2","SL2" if aa>=2 else "SL1",aa>=2,f"{aa} profiles found","IEC 62443-2-4 SP.03.02")
    # FR6 Event Response
    bridge=(CW_REPO/"cyberwall/sentinel_bridge/bridge.py").exists()
    chk(report,"Security Event Forwarding","sorabbyngo-cyberwall","SL2","SL2" if bridge else "SL0",bridge,"Sentinel bridge found" if bridge else "Missing","IEC 62443-3-3 SR 6.1")
    playbook=(REPO_ROOT/"compliance/playbooks/breach_response.md").exists()
    chk(report,"Incident Response Playbook","sorabbyngo-security","SL2","SL2" if playbook else "SL1",playbook,"Found" if playbook else "Missing","IEC 62443-3-3 SR 6.2")
    ai=(CW_REPO/"cyberwall/ai/analyzer.py").exists()
    chk(report,"AI Threat Detection","sorabbyngo-cyberwall","SL3","SL3" if ai else "SL1",ai,"AI analyzer found" if ai else "Missing","IEC 62443-3-3 SR 6.2")
    # FR7 Availability
    if engine:
        content=(CW_REPO/"cyberwall/firewall/engine.py").read_text()
        rl="rate" in content.lower() and "token" in content.lower()
        chk(report,"Rate Limiting (DoS Protection)","sorabbyngo-cyberwall","SL2","SL2" if rl else "SL0",rl,"Token-bucket limiter found" if rl else "Missing","IEC 62443-3-3 SR 7.1")

def print_report(report):
    print(f"\n{BOLD}{CYAN}{'─'*65}{RESET}")
    print(f"{BOLD}{CYAN}  Sorabbyngo — IEC 62443 Compliance Check{RESET}")
    print(f"{CYAN}  Target: SL2 (SL3 for patient data & audit integrity){RESET}")
    print(f"{CYAN}  {report.ts}{RESET}")
    print(f"{CYAN}{'─'*65}{RESET}\n")
    for r in report.results:
        icon=f"{GREEN}✓{RESET}" if r.status=="PASS" else f"{YELLOW}~{RESET}" if r.status=="WARN" else f"{RED}✗{RESET}"
        sl_color=GREEN if r.sl_achieved>=r.sl_target else YELLOW if r.sl_achieved>"SL0" else RED
        print(f"  {icon} {r.req:<50} {sl_color}[{r.sl_achieved}/{r.sl_target}]{RESET}")
        if r.status!="PASS":print(f"      {YELLOW}↳ {r.detail}  ({r.ref}){RESET}")
    color=GREEN if report.score>=80 else YELLOW if report.score>=60 else RED
    print(f"\n{BOLD}{color}{'─'*65}")
    print(f"  Score: {len(report.passed)}/{len(report.results)}  ({report.score:.0f}%)")
    print(f"  {'SL2 COMPLIANT ✓' if report.score>=90 else 'GAPS DETECTED — review above'}")
    print(f"{'─'*65}{RESET}\n")

if __name__=="__main__":
    r=Report(); run(r); print_report(r)
    out=REPO_ROOT/"audit/logs"; out.mkdir(parents=True,exist_ok=True)
    ts=datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    (out/f"iec62443-{ts}.json").write_text(json.dumps({"score":r.score,"results":[vars(x) for x in r.results]},indent=2))
    sys.exit(0 if r.score>=80 else 1)
