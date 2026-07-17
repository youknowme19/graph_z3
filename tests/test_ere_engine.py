import sys
import os

sys.path.insert(0, "/Volumes/WD_Subharup/Major Project/graph_z3")
sys.path.insert(0, "/Volumes/WD_Subharup/Major Project/graph_z3/src")

from core.exploitability_engine import ExploitabilityReasoningEngine, AttackState

def test_ere_engine_counterfactuals():
    mitigations = {"pie": True, "nx": True, "canary": False, "aslr": True}
    
    state = AttackState(
        vulnerability_type="STACK_OVERFLOW",
        function_name="_vuln_stack_overflow",
        binary_offset="0x100000504",
        symbolic_variables=["stdin_input"],
        path_constraints=["c1", "c2"],
        memory_model="STACK_FRAME",
        registers={"pc": "0x41414141"},
        call_stack=["main", "_vuln_stack_overflow"],
        symbolic_memory={},
        sink="_strcpy",
        source="stdin",
        cfg_path=["0x1000004fc", "0x100000504"],
        solver_model=[{"var": "stdin", "hex": "41414141"}],
        witness_input=b"A"*80
    )
    
    engine = ExploitabilityReasoningEngine(mitigations)
    verdict = engine.analyze_exploitability(state)
    
    assert verdict.verdict in ["YES", "LIKELY"]
    assert verdict.hackability_score >= 50.0
    assert verdict.exploit_primitive == "ROP_CHAIN"
    assert len(verdict.counterfactuals) >= 2
    assert any("Canary" in c.mitigation_or_patch for c in verdict.counterfactuals)
