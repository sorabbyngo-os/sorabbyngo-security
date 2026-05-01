#!/usr/bin/env python3
"""Sorabbyngo — Tamper-evident SHA-256 chained audit log writer."""
import argparse, hashlib, json, os, threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

DEFAULT_LOG=Path("/var/log/sorabbyngo"); FALLBACK=Path(__file__).parent/"logs"

class AuditWriter:
    def __init__(self, log_path=None, node_id=None):
        if log_path is None:
            try: DEFAULT_LOG.mkdir(parents=True,exist_ok=True); log_path=DEFAULT_LOG/"audit.jsonl"; log_path.touch()
            except PermissionError: FALLBACK.mkdir(parents=True,exist_ok=True); log_path=FALLBACK/"audit.jsonl"
        self._path=Path(log_path); self._lock=threading.Lock()
        self._node_id=node_id or os.environ.get("SORABBYNGO_NODE_ID","unknown")
        self._prev=self._read_last_hash()

    def _read_last_hash(self):
        if not self._path.exists() or self._path.stat().st_size==0: return "0"*64
        try:
            with open(self._path,"rb") as f:
                f.seek(0,2); f.seek(max(0,f.tell()-4096))
                for line in reversed(f.read().decode(errors="replace").strip().splitlines()):
                    if line.strip():
                        return json.loads(line.strip()).get("sha256_self","0"*64)
        except: pass
        return "0"*64

    @staticmethod
    def _hash(e): return hashlib.sha256(json.dumps({k:v for k,v in e.items() if k!="sha256_self"},sort_keys=True).encode()).hexdigest()

    def write(self,actor,action,resource,outcome,metadata=None,service=None):
        with self._lock:
            e={"ts":datetime.now(timezone.utc).isoformat(),"node_id":self._node_id,
               "service":service or "unknown","actor":actor,"action":action,
               "resource":resource,"outcome":outcome.upper(),"metadata":metadata or {},
               "sha256_prev":self._prev,"sha256_self":""}
            e["sha256_self"]=self._hash(e); self._prev=e["sha256_self"]
            with open(self._path,"a",buffering=1) as f: f.write(json.dumps(e)+"\n")
            return e

    def threat_event(self,threat_type,src_ip,score,blocked):
        return self.write("cyberwall",f"threat.{threat_type}",f"network/{src_ip}",
                         "BLOCKED" if blocked else "DETECTED",{"score":score,"src_ip":src_ip},"cyberwall")

def audit(actor,action,resource,outcome,**kwargs):
    return AuditWriter().write(actor=actor,action=action,resource=resource,outcome=outcome,**kwargs)

if __name__=="__main__":
    p=argparse.ArgumentParser(); p.add_argument("--actor",required=True)
    p.add_argument("--action",required=True); p.add_argument("--resource",required=True)
    p.add_argument("--outcome",default="SUCCESS"); p.add_argument("--log",default=None)
    args=p.parse_args()
    w=AuditWriter(log_path=Path(args.log) if args.log else None)
    print(json.dumps(w.write(args.actor,args.action,args.resource,args.outcome),indent=2))
