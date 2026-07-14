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
            "tool": {
                "driver": {
                    "name": "Neuro-Symbolic Fuzzer",
                    "version": "1.0.0",
                    "rules": [
                        {
                            "id": "SYMBOLIC_PC",
                            "name": "Symbolic Instruction Pointer",
                            "shortDescription": {"text": "Control flow hijacking detected"}
                        },
                        {
                            "id": "STACK_OVERFLOW",
                            "name": "Stack Buffer Overflow",
                            "shortDescription": {"text": "Stack frame memory limit exceeded"}
                        },
                        {
                            "id": "OOB_WRITE",
                            "name": "Out-of-Bounds Write",
                            "shortDescription": {"text": "Heap or global buffer overflow"}
                        },
                        {
                            "id": "OOB_READ",
                            "name": "Out-of-Bounds Read",
                            "shortDescription": {"text": "Information leak via out-of-bounds read"}
                        },
                        {
                            "id": "USE_AFTER_FREE",
                            "name": "Use After Free",
                            "shortDescription": {"text": "Accessing memory after it has been deallocated"}
                        },
                        {
                            "id": "DOUBLE_FREE",
                            "name": "Double Free",
                            "shortDescription": {"text": "Freeing the same pointer twice"}
                        },
                        {
                            "id": "NULL_DEREF",
                            "name": "Null Pointer Dereference",
                            "shortDescription": {"text": "Dereferencing a nullable pointer"}
                        },
                        {
                            "id": "INTEGER_OVERFLOW",
                            "name": "Integer Overflow",
                            "shortDescription": {"text": "Arithmetic wraparound resulting in unexpected bounds"}
                        }
                    ],
                }
            },
            "artifacts": [{"location": {"uri": binary_name}}],
            "results": results,
            "invocations": [{
                "startTimeUtc": datetime.utcnow().isoformat() + "Z",
                "executionSuccessful": True
            }],
        }]
    }
