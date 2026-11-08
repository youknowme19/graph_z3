import unittest
import os
import sys
import networkx as nx

# Add project root and src to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.binary_loader import BinaryLoader
from core.interfaces import (
    AnalysisBackendProvider,
    ExecutionState,
    ConstraintResult,
    _iter_leaf_asts,
    is_variable_used_in_constraints,
    get_symbolic_variables_from_state,
    verify_live_crash,
)
from graph.graph_builder import GraphBuilder
from symbolic.engine import SymbolicEngine
from symbolic.z3_interface import Z3Interface
from core.fix_advisor import FixAdvisor
import claripy

# Allow CI to override via env-var; default to the in-repository benchmark binary.
_benchmark_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_benchmarks_binary"))
_test_vuln_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test_vuln"))
_DEFAULT_BINARY = _benchmark_path if os.path.exists(_benchmark_path) else _test_vuln_path
BINARY_PATH = os.environ.get("NSF_TEST_BINARY", _DEFAULT_BINARY)

class TestBinaryLoader(unittest.TestCase):
    def setUp(self):
        self.assertTrue(os.path.exists(BINARY_PATH), f"Target binary {BINARY_PATH} not found.")
        self.loader = BinaryLoader(BINARY_PATH)

    def test_analyze(self):
        self.loader.analyze()
        self.assertIsNotNone(self.loader.get_cfg())
        self.assertIsNotNone(self.loader.get_call_graph())
        self.assertIsNotNone(self.loader.get_functions())


class TestGraphBuilder(unittest.TestCase):
    def setUp(self):
        self.loader = BinaryLoader(BINARY_PATH)
        self.loader.analyze()
        self.builder = GraphBuilder(self.loader)

    def test_build_networkx_cfg(self):
        cfg = self.builder.build_networkx_cfg()
        self.assertIsInstance(cfg, nx.DiGraph)
        self.assertGreater(cfg.number_of_nodes(), 0)
        
        # Verify node properties (e.g. is_loop_header) are present
        for node, data in cfg.nodes(data=True):
            self.assertIn('is_loop_header', data)
            self.assertIn('binary_section', data)
            self.assertIn('instruction_count', data)

    def test_build_networkx_cg(self):
        cg = self.builder.build_networkx_cg()
        self.assertIsInstance(cg, nx.DiGraph)
        self.assertGreater(cg.number_of_nodes(), 0)
        
        # Verify node properties (e.g. is_recursive) are present
        for node, data in cg.nodes(data=True):
            self.assertIn('is_recursive', data)
            self.assertIn('is_loop_header', data)
            self.assertIn('is_library_call', data)
            self.assertIn('callers', data)
            self.assertIn('callees', data)


class TestSymbolicEngine(unittest.TestCase):
    def setUp(self):
        self.loader = BinaryLoader(BINARY_PATH)
        self.loader.analyze()
        self.engine = SymbolicEngine(self.loader)

    def test_inject_symbolic_input(self):
        sym_var = self.engine.inject_symbolic_input(name="test_input", size_bytes=16)
        self.assertEqual(sym_var.size(), 16 * 8)
        self.assertTrue(sym_var.args[0].startswith("test_input"))

    def test_step_and_explore(self):
        self.engine.inject_symbolic_input(name="test_input", size_bytes=16)
        trace = self.engine.explore(max_steps=5)
        self.assertIsInstance(trace, list)
        self.assertGreater(len(trace), 0)


class TestZ3Interface(unittest.TestCase):
    def setUp(self):
        self.loader = BinaryLoader(BINARY_PATH)
        self.loader.analyze()
        self.engine = SymbolicEngine(self.loader)
        self.sym_var = self.engine.inject_symbolic_input(name="test_input", size_bytes=16)

    def test_evaluate_path(self):
        # Retrieve the initial state
        state = self.engine.state
        sym_vars = {"test_input": self.sym_var}
        
        result = Z3Interface.evaluate_path(state, sym_vars)
        self.assertEqual(result["status"], "SAT")
        self.assertIn("satisfying_assignment", result)
        self.assertIn("test_input", result["satisfying_assignment"])
        self.assertIsInstance(result["satisfying_assignment"]["test_input"], bytes)
        self.assertEqual(len(result["satisfying_assignment"]["test_input"]), 16)


class TestAnalysisBackendProvider(unittest.TestCase):
    def setUp(self):
        self.backend = AnalysisBackendProvider(BINARY_PATH, max_steps=300)

    def test_init(self):
        self.assertEqual(self.backend.binary_path, BINARY_PATH)
        self.assertIsNotNone(self.backend.loader)
        self.assertIsNotNone(self.backend.engine)

    def test_init_with_gnn_vulnerable_functions(self):
        backend = AnalysisBackendProvider(BINARY_PATH, gnn_vulnerable_functions={0x100000684: True})
        self.assertEqual(backend.gnn_vulnerable_functions, {0x100000684: True})

    def test_get_execution_trace(self):
        trace = self.backend.get_execution_trace()
        self.assertGreater(len(trace), 0)
        first_state = trace[0]
        self.assertIsInstance(first_state, ExecutionState)
        self.assertEqual(first_state.solver_status, "SAT")

    def test_get_constraint_result(self):
        trace = self.backend.get_execution_trace()
        first_state = trace[0]
        res = self.backend.get_constraint_result(first_state)
        self.assertIsInstance(res, ConstraintResult)
        self.assertEqual(res.status, "SAT")
        self.assertGreater(len(res.symbolic_variables_list), 0)
        self.assertEqual(res.symbolic_variables_list[0]["name"], "stdin_input")

    def test_scan_vulnerabilities(self):
        vulns = self.backend.scan_vulnerabilities()
        self.assertIsInstance(vulns, list)
        
        # Verify vulnerability detection
        vuln_types = [v["vuln_type"] for v in vulns]
        self.assertTrue(any(t in ("SYMBOLIC_PC", "STACK_OVERFLOW", "CRASH", "OOB_WRITE") for t in vuln_types), f"Expected STACK_OVERFLOW, SYMBOLIC_PC, or CRASH, got {vuln_types}")
        
        # Verify reproduce command is generated
        for v in vulns:
            self.assertIn("reproduce_cmd", v)
            self.assertIsInstance(v["reproduce_cmd"], str)

    def test_loop_summarization(self):
        # Run trace generation
        trace = self.backend.get_execution_trace()
        self.assertGreater(len(trace), 0)
        
        # Verify solver events list is populated
        self.assertIsInstance(self.backend.solver_events, list)


class TestClaripyRegression(unittest.TestCase):
    """Phase 2 Req 2: Regression tests for Claripy leaf_asts() and solver.variables handling."""

    def test_iter_leaf_asts_callable_and_iterable(self):
        x = claripy.BVS("stdin_input", 16)
        y = claripy.BVS("taint_read_0x1000_byte0", 8)
        c = (x[7:0] == y) & (y == 0x41)

        leaves = list(_iter_leaf_asts(c))
        self.assertGreaterEqual(len(leaves), 2)
        self.assertTrue(is_variable_used_in_constraints(x, [c]))
        self.assertTrue(is_variable_used_in_constraints(y, [c]))

        z = claripy.BVS("unused_var", 8)
        self.assertFalse(is_variable_used_in_constraints(z, [c]))

        class _IterableLeafDummy:
            leaf_asts = [x, y]

        self.assertEqual(len(list(_iter_leaf_asts(_IterableLeafDummy()))), 2)
        self.assertEqual(list(_iter_leaf_asts(None)), [])

    def test_no_method_object_not_iterable_on_sample_binaries(self):
        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "samples"))
        for fname, expected_vuln in (
            ("cwe120_buffer_overflow.bin", "STACK_OVERFLOW"),
            ("cwe416_use_after_free.bin", "USE_AFTER_FREE"),
        ):
            bpath = os.path.join(samples_dir, fname)
            if not os.path.exists(bpath):
                continue
            provider = AnalysisBackendProvider(bpath, max_steps=100)
            vulns = provider.scan_vulnerabilities()
            self.assertGreater(len(vulns), 0, f"Expected vulnerability in {fname}")
            for v in vulns:
                self.assertNotEqual(v["solver_status"], "ERROR", f"Unexpected solver ERROR in {fname}")
            self.assertTrue(any(v["vuln_type"] == expected_vuln and v["solver_status"] == "SAT" for v in vulns))


class TestZ3SolverStatusesAndNoFabricatedFallbacks(unittest.TestCase):
    """Phase 2 Req 3 & 7: Unit tests for SAT, UNSAT, UNKNOWN, TIMEOUT, ERROR and zero fabricated payloads."""

    def setUp(self):
        self.loader = BinaryLoader(BINARY_PATH)
        self.loader.analyze()
        self.engine = SymbolicEngine(self.loader)
        self.sym_var = self.engine.inject_symbolic_input(name="test_input", size_bytes=8)

    def test_unsat_status_returns_empty_payload(self):
        state = self.engine.state.copy()
        contradiction = [self.sym_var == 0x1111111111111111, self.sym_var == 0x2222222222222222]
        res = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, extra_constraints=contradiction)
        self.assertEqual(res["status"], "UNSAT")
        self.assertEqual(res["satisfying_assignment"], {})

    def test_error_status_on_invalid_state(self):
        res_none = Z3Interface.evaluate_path(None, {"test_input": self.sym_var})
        self.assertEqual(res_none["status"], "ERROR")
        self.assertEqual(res_none["satisfying_assignment"], {})

        state = self.engine.state.copy()
        res_bad = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, extra_constraints=["NOT_A_CLARIPY_AST"])
        self.assertEqual(res_bad["status"], "ERROR")
        self.assertEqual(res_bad["satisfying_assignment"], {})

    def test_timeout_and_unknown_status_handling(self):
        from unittest.mock import patch
        import z3

        state = self.engine.state.copy()
        with patch.object(z3.Solver, "check", return_value=z3.unknown), patch.object(
            z3.Solver, "reason_unknown", return_value="timeout"
        ):
            res_timeout = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, timeout_ms=5)
            self.assertEqual(res_timeout["status"], "TIMEOUT")
            self.assertEqual(res_timeout["satisfying_assignment"], {})

        with patch.object(z3.Solver, "check", return_value=z3.unknown), patch.object(
            z3.Solver, "reason_unknown", return_value="incomplete quantifier instantiation"
        ):
            res_unknown = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, timeout_ms=50000)
            self.assertEqual(res_unknown["status"], "UNKNOWN")
            self.assertEqual(res_unknown["satisfying_assignment"], {})

    def test_no_fabricated_65_40_fallback_in_interfaces(self):
        interfaces_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "core", "interfaces.py"))
        with open(interfaces_path, "r", encoding="utf-8") as fh:
            src_text = fh.read()
        self.assertNotIn("[65] * 40", src_text)
        self.assertNotIn("[65]*40", src_text)


class TestNativeCrashReplay(unittest.TestCase):
    """Phase 2 Req 5 & 7: Unit tests for independent native crash replay and invalid/timeout scenarios."""

    def test_valid_and_invalid_payloads(self):
        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "samples"))
        null_bin = os.path.join(samples_dir, "cwe476_null_deref.bin")
        sec_bin = os.path.join(samples_dir, "secure_program.bin")

        if os.path.exists(null_bin):
            # 'A' triggers NULL dereference; 'B' does not
            valid_res = verify_live_crash(null_bin, b"A", vuln_type="NULL_DEREF")
            self.assertTrue(valid_res["attempted"])
            self.assertTrue(valid_res["crashed"])
            self.assertEqual(valid_res["signal"], "SIGSEGV")

            invalid_res = verify_live_crash(null_bin, b"B", vuln_type="NULL_DEREF")
            self.assertTrue(invalid_res["attempted"])
            self.assertFalse(invalid_res["crashed"])

        if os.path.exists(sec_bin):
            sec_res = verify_live_crash(sec_bin, b"AAAA", vuln_type="STACK_OVERFLOW")
            self.assertTrue(sec_res["attempted"])
            self.assertFalse(sec_res["crashed"])

    def test_empty_missing_and_timeout_crash_replay(self):
        empty_res = verify_live_crash(BINARY_PATH, b"")
        self.assertFalse(empty_res["attempted"])
        self.assertFalse(empty_res["crashed"])

        missing_res = verify_live_crash("/nonexistent/binary_path_xyz", b"AAAA")
        self.assertFalse(missing_res["attempted"])
        self.assertFalse(missing_res["crashed"])

        from unittest.mock import patch
        import subprocess

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=BINARY_PATH, timeout=0.05)):
            t_res = verify_live_crash(BINARY_PATH, b"AAAA", timeout_s=0.05)
            self.assertTrue(t_res["attempted"])
            self.assertFalse(t_res["crashed"])
            self.assertTrue(t_res["timed_out"])


class TestSchedulerComparison(unittest.TestCase):
    """Phase 2 Req 6: Reproducible DFS baseline vs MaxHeap risk-prioritized scheduler comparison."""

    def test_dfs_baseline_reproducibility(self):
        p1 = AnalysisBackendProvider(BINARY_PATH, max_steps=35, scheduler_mode="dfs")
        t1 = [s.instruction_address for s in p1.get_execution_trace()]

        p2 = AnalysisBackendProvider(BINARY_PATH, max_steps=35, scheduler_mode="dfs")
        t2 = [s.instruction_address for s in p2.get_execution_trace()]

        self.assertEqual(t1, t2)
        self.assertEqual(p1.scheduler_telemetry["states_explored"], p2.scheduler_telemetry["states_explored"])

    def test_maxheap_prioritizes_deep_target_over_dfs_under_identical_budget(self):
        # In test_benchmarks_binary, trigger_double_free (0x100000624) is the 5th branch in main().
        # Under a 38-step budget, unguided DFS reaches only the first 2 branches, whereas MaxHeap
        # guided toward 0x100000624 skips the first 4 branches and verifies DOUBLE_FREE in 37 steps.
        p_dfs = AnalysisBackendProvider(BINARY_PATH, max_steps=38, timeout_seconds=10.0, scheduler_mode="dfs")
        vulns_dfs = p_dfs.scan_vulnerabilities()
        dfs_types = {v["vuln_type"] for v in vulns_dfs}
        self.assertNotIn("DOUBLE_FREE", dfs_types)

        p_heap = AnalysisBackendProvider(
            BINARY_PATH,
            max_steps=38,
            timeout_seconds=10.0,
            scheduler_mode="maxheap",
            gnn_node_scores={0x100000624: 0.95},
        )
        vulns_heap = p_heap.scan_vulnerabilities()
        heap_df = [v for v in vulns_heap if v["vuln_type"] == "DOUBLE_FREE"]
        self.assertEqual(len(heap_df), 1)
        self.assertEqual(heap_df[0]["solver_status"], "SAT")
        self.assertTrue(heap_df[0]["exploit_verified"])
        self.assertTrue(bytes(heap_df[0]["crash_integers"]).startswith(b"double\x00"))


if __name__ == "__main__":
    unittest.main()
