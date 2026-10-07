#!/usr/bin/env python3
"""
03_connector.py
Orchestrate discovery -> validation -> verification.
"""

from __future__ import annotations
import argparse
import json
import subprocess
import sys
from pathlib import Path
from datetime import datetime
import logging

def setup():
    Path("logs").mkdir(exist_ok=True)
    logging.basicConfig(filename="logs/connector.log",level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

def run(cmd):
    logging.info("Running: %s", " ".join(map(str,cmd)))
    p=subprocess.run(cmd,text=True)
    if p.returncode != 0:
        raise RuntimeError(f"Command failed with exit code {p.returncode}: {' '.join(cmd)}")

def validate_candidates(path):
    p=Path(path)
    if not p.exists(): raise RuntimeError(f"Candidate JSON not found: {p}")
    obj=json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(obj,dict) or not isinstance(obj.get("targets"),list):
        raise RuntimeError("Candidate JSON is malformed: missing targets array.")
    total=sum(len(t.get("candidates",[])) for t in obj["targets"])
    if total == 0:
        raise RuntimeError("Candidate JSON contains zero candidates; verification will not run.")
    for t in obj["targets"]:
        for c in t.get("candidates",[]):
            if not c.get("ip"):
                raise RuntimeError("Malformed candidate: missing IP.")
    return obj,total

def main():
    setup()
    ap=argparse.ArgumentParser(description="Run the complete off-ASN EASM workflow.")
    ap.add_argument("--input",required=True,help="targets.xlsx/json/csv")
    ap.add_argument("--candidate-json",default="off_asn_candidates.json")
    ap.add_argument("--candidate-output",default="off_asn_candidates.xlsx")
    ap.add_argument("--verification-output",default="verified_ip_ranges.xlsx")
    ap.add_argument("--config",default="config.json")
    ap.add_argument("--workers",type=int)
    ap.add_argument("--timeout",type=float)
    ap.add_argument("--overwrite",action="store_true")
    ap.add_argument("--verbose",action="store_true")
    args=ap.parse_args()
    py=sys.executable
    try:
        print("[1/4] Loading target input...")
        if not Path(args.input).exists(): raise RuntimeError(f"Input not found: {args.input}")
        print("[2/4] Running off-ASN discovery...")
        cmd=[py,"02_off_asn_discovery.py","--input",args.input,
             "--output",args.candidate_output,"--json-output",args.candidate_json,
             "--config",args.config]
        if args.workers: cmd += ["--workers",str(args.workers)]
        if args.timeout: cmd += ["--timeout",str(args.timeout)]
        if args.overwrite: cmd += ["--overwrite"]
        if args.verbose: cmd += ["--verbose"]
        run(cmd)
        print("[3/4] Passing candidate JSON to verification engine...")
        obj,total=validate_candidates(args.candidate_json)
        print(f"    Validated {total} candidates.")
        print("[4/4] Generating verified IP range report...")
        cmd=[py,"04_ip_verification.py","--input",args.candidate_json,
             "--output",args.verification_output,"--config",args.config]
        if args.workers: cmd += ["--workers",str(args.workers)]
        if args.timeout: cmd += ["--timeout",str(args.timeout)]
        if args.overwrite: cmd += ["--overwrite"]
        if args.verbose: cmd += ["--verbose"]
        run(cmd)
        final=Path(args.verification_output)
        final_json=final.with_suffix(".json")
        print("="*50)
        print("EASM OFF-ASN DISCOVERY COMPLETE")
        print("="*50)
        print(f"Candidates: {total}")
        print(f"Candidate file: {Path(args.candidate_output).resolve()}")
        print(f"Final verified file: {final.resolve()}")
        if final_json.exists(): print(f"Final verified JSON: {final_json.resolve()}")
        print("="*50)
        return 0
    except Exception as e:
        logging.exception("Connector failed")
        print(f"ERROR: {e}",file=sys.stderr)
        return 1

if __name__=="__main__":
    raise SystemExit(main())
