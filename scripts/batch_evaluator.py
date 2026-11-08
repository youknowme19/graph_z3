"""
batch_evaluator.py — Automated multi-binary symbolic scan runner.
Extracts thin ARM64 slices of system binaries and runs graph_z3 across them.
"""
import os
import sys
import json
import time
import subprocess
from typing import List, Dict, Any

# Ensure project imports resolve
script_dir = os.path.abspath(os.path.dirname(__file__))
root_dir = os.path.abspath(os.path.join(script_dir, ".."))
src_dir = os.path.join(root_dir, "src")
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from core.interfaces import AnalysisBackendProvider

BINARIES = [
    "file", "bzip2", "gzip", "hexdump", "od",
    "diff", "patch", "sort", "uniq", "tr",
    "wc", "cut", "fold", "fmt", "pr",
    "csplit", "split", "head", "tail", "nl",
    "paste", "join", "comm", "m4", "sed",
    "awk", "strings", "nm", "size", "base64",
    "cksum", "rev", "look", "expand", "unexpand",
    "col", "column", "tsort", "cmp"
]

TMP_DIR = "/tmp/thin_bins"
RESULTS_FILE = os.path.expanduser("~/Downloads/batch_scan_50_results.json")

def prepare_thin_binary(name: str) -> str:
    os.makedirs(TMP_DIR, exist_ok=True)
    src_path = f"/usr/bin/{name}"
    out_path = os.path.join(TMP_DIR, f"{name}_arm64")
    if os.path.exists(out_path):
        return out_path
    if not os.path.exists(src_path):
        return None
    try:
        cmd = ["lipo", src_path, "-thin", "arm64e", "-output", out_path]
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return out_path
    except Exception:
        # If arm64e fails, try arm64 or direct copy
        try:
            cmd = ["lipo", src_path, "-thin", "arm64", "-output", out_path]
            subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return out_path
        except Exception:
            return None

def scan_target(name: str, path: str, max_steps: int = 1000, symbolic_size: int = 128) -> Dict[str, Any]:
    print(f"\n=======================================================")
    print(f"[*] Scanning [{name}] ({os.path.getsize(path)/1024:.1f} KB) ...")
    print(f"=======================================================")
    t0 = time.time()
    try:
        backend = AnalysisBackendProvider(
            binary_path=path,
            max_steps=max_steps,
            symbolic_input_size=symbolic_size,
            original_filename=name
        )
        vulns = backend.scan_vulnerabilities()
        elapsed = round(time.time() - t0, 2)
        print(f"[+] [{name}] completed in {elapsed}s: Found {len(vulns)} vulnerability(ies).")
        for idx, v in enumerate(vulns):
            print(f"    -> [{idx+1}] {v.get('vuln_type')} ({v.get('vuln_severity')}) at {v.get('address')} in {v.get('function_name')}")
        return {
            "binary": name,
            "path": path,
            "elapsed_seconds": elapsed,
            "vulnerabilities_found": len(vulns),
            "findings": vulns,
            "status": "SUCCESS"
        }
    except Exception as e:
        elapsed = round(time.time() - t0, 2)
        print(f"[-] [{name}] failed after {elapsed}s: {e}")
        return {
            "binary": name,
            "path": path,
            "elapsed_seconds": elapsed,
            "vulnerabilities_found": 0,
            "error": str(e),
            "status": "ERROR"
        }

def main():
    print("=================================================================")
    print("  GRAPH_Z3 — Automated Batch Vulnerability Evaluation")
    print(f"  Target Queue: {len(BINARIES)} popular software binaries")
    print("  Parameters: Max Steps=1000, Symbolic Input=128B")
    print("=================================================================")
    
    summary = []
    
    for idx, name in enumerate(BINARIES):
        print(f"\n({idx+1}/{len(BINARIES)}) Preparing {name}...")
        thin_bin = prepare_thin_binary(name)
        if not thin_bin:
            print(f"[-] Skipping {name}: unable to extract thin arm64 binary")
            continue
        res = scan_target(name, thin_bin, max_steps=1000, symbolic_size=128)
        summary.append(res)
        
        # Save incremental results after each binary
        try:
            with open(RESULTS_FILE, "w") as f:
                json.dump(summary, f, indent=2, default=str)
        except Exception:
            pass

    print("\n\n=================================================================")
    print("  BATCH SCAN COMPLETE")
    print("=================================================================")
    total_vulns = sum(s["vulnerabilities_found"] for s in summary)
    print(f"Total binaries analyzed: {len(summary)}")
    print(f"Total confirmed vulnerabilities: {total_vulns}")
    print(f"Detailed report saved to: {RESULTS_FILE}")

if __name__ == "__main__":
    main()
