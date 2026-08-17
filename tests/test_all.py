import unittest
import os
import sys
import networkx as nx

# Add project root and src to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.binary_loader import BinaryLoader
from core.interfaces import AnalysisBackendProvider, ExecutionState, ConstraintResult
from graph.graph_builder import GraphBuilder
from symbolic.engine import SymbolicEngine
from symbolic.z3_interface import Z3Interface
from core.fix_advisor import FixAdvisor

# Allow CI to override via env-var; default to the pre-built test binary
# sitting next to the project root (one level above the tests/ directory).
_test_vuln_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "test_vuln"))
_benchmark_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_benchmarks_binary"))
_DEFAULT_BINARY = _test_vuln_path if os.path.exists(_test_vuln_path) else _benchmark_path
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


if __name__ == "__main__":
    unittest.main()
