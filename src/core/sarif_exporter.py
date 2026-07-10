import json
from typing import List, Dict, Any
from datetime import datetime

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA  = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json"

SEVERITY_MAP = {
    "CRITICAL": "error",
    "HIGH": "warning",
    "MEDIUM": "note",
    "LOW": "note",
}

def findings_to_sarif(vulns: List[Dict[str, Any]], binary_name: str) -> dict:
    results = []
    for v in vulns:
        addr = v.get("address", "0x0")
        primitive = v.get("exploit_primitive") or {}
        
        # Build message
        msg_parts = [v.get("vuln_details", "")]
        if primitive.get("title"):
            msg_parts.append(f"Exploit Primitive: {primitive['title']}")
        if primitive.get("attacker_capability"):
            msg_parts.append(f"Attacker Capability: {primitive['attacker_capability']}")
            
        rule_id = v.get("vuln_type", "UNKNOWN")
        
        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_MAP.get(v.get("vuln_severity", ""), "warning"),
            "message": {"text": "\n".join(msg_parts)},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": binary_name},
                    "region": {
                        "startLine": 1,
                        "snippet": {"text": f"Instruction Address: {addr}"}
                    }
                }
            }],
            "properties": {
                "exploit_bytes": v.get("exploit_vars", []),
                "reproduce_cmd": v.get("reproduce_cmd", ""),
                "fix_advice": v.get("fix_advice", {}),
                "cvss_score": primitive.get("cvss_base_score", 5.0),
                "call_stack": v.get("call_stack", []),
            }
        })
        
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
