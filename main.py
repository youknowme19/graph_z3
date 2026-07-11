import sys
import os
import argparse
import json

# Add root directory to sys.path so we can run directly as a script
root_dir = os.path.abspath(os.path.dirname(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from core.interfaces import AnalysisBackendProvider
from core.sarif_exporter import findings_to_sarif
from ui.app import create_app

_DEBUG_MODE = os.environ.get("NSF_DEBUG", "0").strip() == "1"
_PORT       = int(os.environ.get("NSF_PORT", "8050"))

def cli_scan(binary_path: str, output_json: str = None, output_sarif: str = None, max_steps: int = 300) -> int:
    """Headless scan mode — runs symbolic analysis and exports reports."""
    print("========================================")
    print("Neuro-Symbolic Fuzzer — Headless Scan")
    print("========================================")
    print(f"Target Binary: {binary_path}")
    print(f"Max depth steps: {max_steps}")
    print("Analyzing binary with angr...")

    try:
        backend = AnalysisBackendProvider(binary_path, max_steps=max_steps)
        vulns = backend.scan_vulnerabilities()
    except Exception as e:
        print(f"[-] Analysis engine error: {e}", file=sys.stderr)
        return 2

    print(f"\n[+] Analysis complete: found {len(vulns)} vulnerability(ies).")

    # Output to stdout summary
    for idx, v in enumerate(vulns):
        print(f"  [{idx+1}] {v['vuln_type']} ({v['vuln_severity']}) at {v['address']} in {v['function_name']}")
        print(f"      Details: {v['vuln_details']}")
        primitive = v.get("exploit_primitive") or {}
        if primitive.get("title"):
            print(f"      Exploit: {primitive['title']} (CVSS {primitive['cvss_base_score']})")

    # Export formats
    if output_json:
        try:
            with open(output_json, "w") as f:
                json.dump(vulns, f, indent=2, default=str)
