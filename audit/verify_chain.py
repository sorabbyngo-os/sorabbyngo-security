#!/usr/bin/env python3
"""Sorabbyngo — Audit Chain Verifier. Usage: python3 audit/verify_chain.py [file.jsonl] [--all]"""
import argparse, hashlib, json, sys
from pathlib import Path

GREEN="\033[92m"; RED="\033[91m"; RESET="\033[0m"; BOLD="\033[1m"

def hash_entry(e):
    return hashlib.sha256(json.dumps({k:v for k,v in e.items() if k!="sha256_self"},sort_keys=True).encode()).hexdigest()

def verify_file(path):
    errors=[]; count=0; prev="0"*64
    with open(path) as f:
        for i,line in enumerate(f,1):
            if not line.strip(): continue
            try: e=json.loads(line)
            except: errors.append(f"Line {i}: invalid JSON"); continue
            count+=1
            if e.get("sha256_prev","")!=prev: errors.append(f"Line {i}: sha256_prev mismatch — chain broken")
            computed=hash_entry(e)
            if e.get("sha256_self","")!=computed: errors.append(f"Line {i}: sha256_self mismatch — entry tampered")
            prev=e.get("sha256_self",computed)
    return len(errors)==0, count, errors

def main():
    p=argparse.ArgumentParser(); p.add_argument("file",nargs="?"); p.add_argument("--all",action="store_true"); args=p.parse_args()
    logs=Path(__file__).parent.parent/"audit"/"logs"
    print(f"\n{BOLD}Sorabbyngo Audit Chain Verifier{RESET}\n{'─'*50}")
    ok=True
    if args.all or not args.file:
        files=sorted(logs.glob("*.jsonl"))
        if not files: print("No .jsonl files found"); sys.exit(0)
        for f in files:
            good,count,errs=verify_file(f)
            print(f"  {GREEN}✓{RESET} {f.name} ({count} entries)" if good else f"  {RED}✗{RESET} {f.name} — {len(errs)} error(s)")
            for e in errs: print(f"    {RED}{e}{RESET}")
            if not good: ok=False
    else:
        path=Path(args.file)
        good,count,errs=verify_file(path)
        print(f"  {GREEN}✓ INTACT{RESET}  {path.name} ({count} entries)" if good else f"  {RED}✗ TAMPERED{RESET}  {path.name}")
        for e in errs: print(f"  {RED}{e}{RESET}")
        ok=good
    print("─"*50)
    print(f"{GREEN}{BOLD}All chains intact.{RESET}\n" if ok else f"{RED}{BOLD}Chain violation detected!{RESET}\n")
    sys.exit(0 if ok else 1)

if __name__=="__main__": main()
