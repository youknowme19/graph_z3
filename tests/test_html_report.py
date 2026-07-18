import os
import sys

sys.path.insert(0, "/Volumes/WD_Subharup/Major Project/graph_z3")
sys.path.insert(0, "/Volumes/WD_Subharup/Major Project/graph_z3/src")

from core.html_report_generator import generate_enterprise_html_report

def test_generate_html_report(tmp_path):
    binary_info = {"filename": "test_vuln", "size_bytes": 45000, "arch": "AARCH64"}
    vulns = [{
        "vuln_type": "STACK_OVERFLOW",
        "vuln_severity": "CRITICAL",
        "address": "0x100000504",
        "function_name": "_vuln_stack_overflow",
        "vuln_details": "Stack buffer overflow in strcpy",
        "reproduce_cmd": "python3 -c \"print('A'*80)\" | ./test_vuln",
        "exploit_primitive": {
            "cwe": "CWE-121: Stack Overflow",
            "cvss_base_score": 9.8,
            "attacker_capability": "Arbitrary Code Execution",
            "reliability": "HIGH"
        }
    }]
    engine_metrics = {"cfg_nodes": 45, "cfg_edges": 60, "active_states": 3, "total_sym_vars": 12, "max_solver_time": 0.45}
    mitigations = {"pie": True, "nx": True, "aslr": True, "canary": False, "relro": "Partial RELRO"}

    out_file = str(tmp_path / "report.html")
    res = generate_enterprise_html_report(binary_info, vulns, engine_metrics, mitigations, output_filename=out_file)
    
    assert os.path.exists(res)
    with open(res, "r") as f:
        content = f.read()
    assert "Neuro-Symbolic Security Report" in content
    assert "STACK_OVERFLOW" in content
    assert "CRITICAL RISK" in content
