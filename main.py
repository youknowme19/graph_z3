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
            print(f"[+] Saved JSON report to: {output_json}")
        except Exception as e:
            print(f"[-] Failed to write JSON: {e}", file=sys.stderr)

    if output_sarif:
        try:
            sarif = findings_to_sarif(vulns, os.path.basename(binary_path))
            with open(output_sarif, "w") as f:
                json.dump(sarif, f, indent=2)
            print(f"[+] Saved SARIF report to: {output_sarif}")
        except Exception as e:
            print(f"[-] Failed to write SARIF: {e}", file=sys.stderr)

    # Return exit code: 1 if high/critical vulns found, else 0
    has_critical = any(v.get("vuln_severity") in ("CRITICAL", "HIGH") for v in vulns)
    return 1 if has_critical else 0

def cli_main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="Neuro-Symbolic Fuzzer and Vulnerability Verifier")
    parser.add_argument("--scan", type=str, help="Run a headless vulnerability scan on target binary")
    parser.add_argument("--output-json", type=str, help="Path to save JSON report file")
    parser.add_argument("--output-sarif", type=str, help="Path to save SARIF report file")
    parser.add_argument("--max-steps", type=int, default=300, help="Maximum execution trace depth (default: 300)")
    parser.add_argument("--server", action="store_true", help="Explicitly start interactive Dash server (default behavior if no args)")

    args = parser.parse_args()

    # If --scan is requested, run headless
    if args.scan:
        sys.exit(cli_scan(
            binary_path=args.scan,
            output_json=args.output_json,
            output_sarif=args.output_sarif,
            max_steps=args.max_steps
        ))

    # Otherwise run Dash server
    print("========================================")
    print("Neuro-Symbolic Fuzzer UI Initialization")
    print("========================================")
    if _DEBUG_MODE:
        print("⚠  DEBUG MODE ENABLED  (NSF_DEBUG=1) — do NOT expose to the internet")
    print(f"Starting interactive viewer on port {_PORT}...")
    print(f"Please open your web browser to http://127.0.0.1:{_PORT}")
    print("You can upload your binary directly from the web portal.\n")

    app = create_app()
    app.run(debug=_DEBUG_MODE, port=_PORT, host="127.0.0.1")

if __name__ == "__main__":
    cli_main()
