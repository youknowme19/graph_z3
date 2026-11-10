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

try:
    from tests.test_timeout_regression import TestTimeoutRegression
except ImportError:
    from test_timeout_regression import TestTimeoutRegression

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
    """Phase 2 Req 3 & 7: Unit tests for SAT, UNSAT, UNKNOWN, TIMEOUT, ERROR, push/pop isolation, and zero fabricated payloads."""

    def setUp(self):
        self.loader = BinaryLoader(BINARY_PATH)
        self.loader.analyze()
        self.engine = SymbolicEngine(self.loader)
        self.sym_var = self.engine.inject_symbolic_input(name="test_input", size_bytes=8)

    def test_sat_ascii_and_non_ascii_and_push_pop_isolation(self):
        state = self.engine.state.copy()
        # 1. SAT with ASCII-compatible constraint (byte 0 == 'Z')
        c_ascii = [self.sym_var[63:56] == ord("Z")]
        res_sat = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, extra_constraints=c_ascii)
        self.assertEqual(res_sat["status"], "SAT")
        witness_ascii = res_sat["satisfying_assignment"].get("test_input")
        self.assertIsInstance(witness_ascii, bytes)
        self.assertEqual(len(witness_ascii), 8)
        self.assertEqual(witness_ascii[0], ord("Z"))
        # Remaining unconstrained bytes should be printable ASCII [0x20, 0x7e]
        for b in witness_ascii[1:]:
            self.assertTrue(0x20 <= b <= 0x7E, f"Expected printable ASCII byte, got {hex(b)}")

        # 2. Base state evaluation (no extra_constraints) caches solver_obj with 0 active push scopes
        state_base = self.engine.state.copy()
        state_base.solver.add(self.sym_var[63:56] == ord("M"))
        res_base = Z3Interface.evaluate_path(state_base, {"test_input": self.sym_var})
        self.assertEqual(res_base["status"], "SAT")
        parent_solver = res_base["solver_obj"]
        self.assertIsNotNone(parent_solver)
        self.assertEqual(parent_solver.num_scopes(), 0)

        # 3. Child state requiring non-ASCII byte (byte 1 == 0x01, outside 0x20..0x7e) must still succeed
        # when cloning parent_solver (proving temporary ASCII beautification constraints were popped!)
        state_non_ascii = state_base.copy()
        state_non_ascii.solver.add(self.sym_var[55:48] == 0x01)
        res_non_ascii = Z3Interface.evaluate_path(
            state_non_ascii,
            {"test_input": self.sym_var},
            parent_solver=parent_solver,
            parent_constraints=list(state_base.solver.constraints),
        )
        self.assertEqual(res_non_ascii["status"], "SAT")
        self.assertIsNotNone(res_non_ascii["solver_obj"])
        self.assertEqual(res_non_ascii["solver_obj"].num_scopes(), 0)
        w_non_ascii = res_non_ascii["satisfying_assignment"]["test_input"]
        self.assertEqual(w_non_ascii[0], ord("M"))
        self.assertEqual(w_non_ascii[1], 0x01)

        # 4. Failed child evaluation (UNSAT) using parent_solver must not pollute parent_solver
        state_unsat_child = state_base.copy()
        state_unsat_child.solver.add(self.sym_var[63:56] == ord("Q"))  # contradicts 'M'
        res_unsat_child = Z3Interface.evaluate_path(
            state_unsat_child,
            {"test_input": self.sym_var},
            parent_solver=parent_solver,
            parent_constraints=list(state_base.solver.constraints),
        )
        self.assertEqual(res_unsat_child["status"], "UNSAT")
        self.assertEqual(res_unsat_child["satisfying_assignment"], {})
        self.assertIsNone(res_unsat_child["solver_obj"])
        self.assertEqual(parent_solver.num_scopes(), 0)

        # Sibling state cloned from the same parent_solver after the failed child must still be SAT
        state_sibling = state_base.copy()
        state_sibling.solver.add(self.sym_var[47:40] == 0xFF)
        res_sibling = Z3Interface.evaluate_path(
            state_sibling,
            {"test_input": self.sym_var},
            parent_solver=parent_solver,
            parent_constraints=list(state_base.solver.constraints),
        )
        self.assertEqual(res_sibling["status"], "SAT")
        self.assertEqual(res_sibling["satisfying_assignment"]["test_input"][0], ord("M"))
        self.assertEqual(res_sibling["satisfying_assignment"]["test_input"][2], 0xFF)

    def test_unsat_status_returns_empty_payload(self):
        state = self.engine.state.copy()
        contradiction = [self.sym_var == 0x1111111111111111, self.sym_var == 0x2222222222222222]
        res = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, extra_constraints=contradiction)
        self.assertEqual(res["status"], "UNSAT")
        self.assertEqual(res["satisfying_assignment"], {})
        self.assertIsNone(res["solver_obj"])

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
            self.assertIsNone(res_timeout["solver_obj"])

        with patch.object(z3.Solver, "check", return_value=z3.unknown), patch.object(
            z3.Solver, "reason_unknown", return_value="incomplete quantifier instantiation"
        ):
            res_unknown = Z3Interface.evaluate_path(state, {"test_input": self.sym_var}, timeout_ms=50000)
            self.assertEqual(res_unknown["status"], "UNKNOWN")
            self.assertEqual(res_unknown["satisfying_assignment"], {})
            self.assertIsNone(res_unknown["solver_obj"])

    def test_unsuccessful_solver_states_never_produce_witness_in_scan(self):
        from unittest.mock import patch

        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "samples"))
        null_bin = os.path.join(samples_dir, "cwe476_null_deref.bin")
        if not os.path.exists(null_bin):
            return

        for fake_status in ("UNSAT", "UNKNOWN", "TIMEOUT", "ERROR"):
            mock_ret = {
                "status": fake_status,
                "constraints_evaluated": [],
                "satisfying_assignment": {},
                "solver_time_ms": 1.0,
                "queries_count": 1,
                "z3_statistics": "N/A",
                "solver_obj": None,
            }
            with patch.object(Z3Interface, "evaluate_path", return_value=mock_ret):
                provider = AnalysisBackendProvider(null_bin, max_steps=40)
                reports = provider.scan_vulnerabilities()
                self.assertGreater(len(reports), 0)
                for rep in reports:
                    self.assertEqual(rep["solver_status"], fake_status)
                    self.assertEqual(rep["crash_integers"], [])
                    self.assertEqual(rep["crash_length"], 0)
                    self.assertEqual(rep["exploit_vars"], [])
                    self.assertEqual(rep["reproduce_cmd"], "")
                    self.assertFalse(rep["sat_witness_generated"])
                    self.assertFalse(rep["exploit_verified"])
                    self.assertFalse(rep["crash_verification"]["attempted"])
                    self.assertFalse(rep["crash_verification"]["crashed"])

    def test_no_fabricated_65_40_fallback_in_interfaces(self):
        interfaces_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "core", "interfaces.py"))
        with open(interfaces_path, "r", encoding="utf-8") as fh:
            src_text = fh.read()
        self.assertNotIn("[65] * 40", src_text)
        self.assertNotIn("[65]*40", src_text)


class TestNativeCrashReplay(unittest.TestCase):
    """Phase 2 Req 1, 5 & 7: Unit tests for native crash replay, channel isolation, benign control, and signal corroboration."""

    def test_valid_and_invalid_payloads(self):
        samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "samples"))
        null_bin = os.path.join(samples_dir, "cwe476_null_deref.bin")
        uaf_bin = os.path.join(samples_dir, "cwe416_use_after_free.bin")
        bof_bin = os.path.join(samples_dir, "cwe120_buffer_overflow.bin")
        sec_bin = os.path.join(samples_dir, "secure_program.bin")

        if os.path.exists(null_bin):
            # 'A' triggers NULL dereference; 'B' is a benign control / invalid witness
            valid_res = verify_live_crash(null_bin, b"A", vuln_type="NULL_DEREF", input_channel="stdin")
            self.assertTrue(valid_res["attempted"])
            self.assertEqual(valid_res["input_channel"], "stdin")
            self.assertIsNotNone(valid_res["witness_sha256"])
            self.assertTrue(valid_res["crashed"])
            self.assertTrue(valid_res["expected_vuln_crash"])
            self.assertFalse(valid_res["unrelated_crash"])
            self.assertFalse(valid_res["benign_control_crashed"])
            self.assertEqual(valid_res["terminating_signal"], "SIGSEGV")
            self.assertEqual(valid_res["replay_mode"], "native")

            invalid_res = verify_live_crash(null_bin, b"B", vuln_type="NULL_DEREF", input_channel="stdin")
            self.assertTrue(invalid_res["attempted"])
            self.assertFalse(invalid_res["crashed"])
            self.assertFalse(invalid_res["expected_vuln_crash"])
            self.assertEqual(invalid_res["returncode"], 0)
            self.assertIsNone(invalid_res["terminating_signal"])

        if os.path.exists(uaf_bin):
            # 'X' triggers UAF under GuardMalloc; 'A' is an invalid witness that exits 0
            uaf_valid = verify_live_crash(uaf_bin, b"X", vuln_type="USE_AFTER_FREE", input_channel="stdin")
            self.assertTrue(uaf_valid["crashed"])
            self.assertTrue(uaf_valid["expected_vuln_crash"])
            self.assertEqual(uaf_valid["terminating_signal"], "SIGSEGV")
            self.assertEqual(uaf_valid["replay_mode"], "native+libgmalloc")

            uaf_invalid = verify_live_crash(uaf_bin, b"A", vuln_type="USE_AFTER_FREE", input_channel="stdin")
            self.assertFalse(uaf_invalid["crashed"])
            self.assertFalse(uaf_invalid["expected_vuln_crash"])

        if os.path.exists(bof_bin):
            # 48 bytes overflows 32-byte buffer via ___strcpy_chk; 8 bytes is benign.
            # On macOS ARM64, ___strcpy_chk traps directly with brk #0x1 without emitting stderr diagnostic.
            # Under strengthened attribution rule, uncorroborated SIGTRAP is classified as UNVERIFIED_ABNORMAL_TERMINATION.
            bof_valid = verify_live_crash(bof_bin, b"B" * 48, vuln_type="STACK_OVERFLOW", input_channel="stdin")
            self.assertTrue(bof_valid["crashed"])
            self.assertEqual(bof_valid["terminating_signal"], "SIGTRAP")
            self.assertEqual(bof_valid["classification"], "UNVERIFIED_ABNORMAL_TERMINATION")
            self.assertFalse(bof_valid["expected_vuln_crash"])
            self.assertIn("fortify_chk_symbol_present(___strcpy_chk)", bof_valid["corroborating_evidence"])
            self.assertIn("sub_boundary_truncated_witness_8B_survived", bof_valid["corroborating_evidence"])
            self.assertIn("insufficient_runtime_diagnostic_classified_unverified_abnormal_termination", bof_valid["corroborating_evidence"])

            bof_short = verify_live_crash(bof_bin, b"B" * 8, vuln_type="STACK_OVERFLOW", input_channel="stdin")
            self.assertFalse(bof_short["crashed"])
            self.assertFalse(bof_short["expected_vuln_crash"])

        if os.path.exists(sec_bin):
            sec_res = verify_live_crash(sec_bin, b"A" * 64, vuln_type="STACK_OVERFLOW", input_channel="stdin")
            self.assertTrue(sec_res["attempted"])
            self.assertFalse(sec_res["crashed"])
            self.assertFalse(sec_res["expected_vuln_crash"])

    def test_channel_isolation_stdin_vs_argv_vs_function_arg(self):
        from unittest.mock import patch
        import subprocess

        recorded_calls = []

        def _fake_run(cmd, input=None, stdout=None, stderr=None, timeout=None, env=None):
            recorded_calls.append({"cmd": list(cmd), "input": input, "env": env})
            proc = subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            return proc

        with patch("subprocess.run", side_effect=_fake_run):
            # 1. stdin channel: must pass input=b"hello" and cmd=[BINARY_PATH] (no argv[1])
            recorded_calls.clear()
            r_stdin = verify_live_crash(BINARY_PATH, b"hello", vuln_type="NULL_DEREF", input_channel="stdin")
            self.assertEqual(r_stdin["input_channel"], "stdin")
            self.assertEqual(recorded_calls[0]["cmd"], [BINARY_PATH])
            self.assertEqual(recorded_calls[0]["input"], b"hello")

            # 2. argv channel: must pass cmd=[BINARY_PATH, "arg_val"] and input=None (never fed to stdin)
            recorded_calls.clear()
            r_argv = verify_live_crash(
                BINARY_PATH, b"arg_val\x00ignored", vuln_type="NULL_DEREF", input_channel="argv"
            )
            self.assertEqual(r_argv["input_channel"], "argv")
            self.assertEqual(recorded_calls[0]["cmd"], [BINARY_PATH, "arg_val"])
            self.assertIsNone(recorded_calls[0]["input"])

            # 3. function_arg channel: must not invoke subprocess at all and classify as NOT_REPLAYABLE
            recorded_calls.clear()
            r_fn = verify_live_crash(BINARY_PATH, b"in_mem_buf", vuln_type="OOB_WRITE", input_channel="function_arg")
            self.assertFalse(r_fn["attempted"])
            self.assertEqual(r_fn["input_channel"], "function_arg")
            self.assertEqual(r_fn["classification"], "NOT_REPLAYABLE")
            self.assertEqual(r_fn["replay_status"], "NOT_REPLAYABLE")
            self.assertFalse(r_fn["expected_vuln_crash"])
            self.assertEqual(len(recorded_calls), 0)

            # 4. Unlinked object file (.o): must classify as NOT_REPLAYABLE
            r_obj = verify_live_crash("/dummy/path/module.o", b"payload", vuln_type="STACK_OVERFLOW", input_channel="stdin")
            self.assertFalse(r_obj["attempted"])
            self.assertEqual(r_obj["classification"], "NOT_REPLAYABLE")
            self.assertEqual(r_obj["replay_status"], "NOT_REPLAYABLE")
            self.assertFalse(r_obj["expected_vuln_crash"])

    def test_unconditional_crash_and_uncorroborated_sigtrap_rejected(self):
        from unittest.mock import patch
        import subprocess

        # 1. Binary that crashes on both witness AND benign control input -> unrelated_crash=True, expected_vuln_crash=False
        def _always_segv(cmd, input=None, **kwargs):
            return subprocess.CompletedProcess(args=cmd, returncode=-11, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=_always_segv):
            res_unrel = verify_live_crash(BINARY_PATH, b"witness", vuln_type="NULL_DEREF", input_channel="stdin")
            self.assertTrue(res_unrel["crashed"])
            self.assertTrue(res_unrel["benign_control_crashed"])
            self.assertTrue(res_unrel["unrelated_crash"])
            self.assertFalse(res_unrel["expected_vuln_crash"])

        # 2. SIGTRAP on NULL_DEREF (even when benign control survives) -> rejected (expected_vuln_crash=False)
        def _sigtrap_on_witness_only(cmd, input=None, **kwargs):
            rc = -5 if input == b"witness_trap" else 0
            return subprocess.CompletedProcess(args=cmd, returncode=rc, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=_sigtrap_on_witness_only):
            res_trap_null = verify_live_crash(
                BINARY_PATH, b"witness_trap", vuln_type="NULL_DEREF", input_channel="stdin"
            )
            self.assertTrue(res_trap_null["crashed"])
            self.assertEqual(res_trap_null["terminating_signal"], "SIGTRAP")
            self.assertFalse(res_trap_null["benign_control_crashed"])
            self.assertEqual(res_trap_null["classification"], "UNVERIFIED_ABNORMAL_TERMINATION")
            self.assertFalse(res_trap_null["expected_vuln_crash"])

        # 3. SIGTRAP on STACK_OVERFLOW where 8-byte truncated prefix ALSO traps -> rejected
        def _sigtrap_even_when_truncated(cmd, input=None, **kwargs):
            rc = 0 if input == b"0\n" else -5
            return subprocess.CompletedProcess(args=cmd, returncode=rc, stdout=b"", stderr=b"")

        with patch("subprocess.run", side_effect=_sigtrap_even_when_truncated):
            res_trap_bof = verify_live_crash(
                BINARY_PATH, b"W" * 48, vuln_type="STACK_OVERFLOW", input_channel="stdin"
            )
            self.assertTrue(res_trap_bof["crashed"])
            self.assertEqual(res_trap_bof["terminating_signal"], "SIGTRAP")
            self.assertEqual(res_trap_bof["classification"], "UNVERIFIED_ABNORMAL_TERMINATION")
            self.assertFalse(res_trap_bof["expected_vuln_crash"])

        # 4. SIGTRAP on STACK_OVERFLOW WITH runtime stderr diagnostic -> corroborated (expected_vuln_crash=True, VERIFIED_EXPLOIT)
        def _sigtrap_with_stderr_diagnostic(cmd, input=None, **kwargs):
            if input == b"0\n" or (input and len(input) <= 8):
                return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=b"", stderr=b"")
            return subprocess.CompletedProcess(
                args=cmd,
                returncode=-5,
                stdout=b"",
                stderr=b"*** buffer overflow detected ***: terminated\n",
            )

        with patch("subprocess.run", side_effect=_sigtrap_with_stderr_diagnostic):
            res_corrob = verify_live_crash(
                BINARY_PATH, b"W" * 48, vuln_type="STACK_OVERFLOW", input_channel="stdin"
            )
            self.assertTrue(res_corrob["crashed"])
            self.assertEqual(res_corrob["terminating_signal"], "SIGTRAP")
            self.assertTrue(res_corrob["expected_vuln_crash"])
            self.assertEqual(res_corrob["classification"], "VERIFIED_EXPLOIT")
            self.assertIn("runtime_diagnostic_corroborates_fortify_overflow", res_corrob["corroborating_evidence"])

    def test_empty_missing_and_timeout_crash_replay(self):
        empty_res = verify_live_crash(BINARY_PATH, b"")
        self.assertFalse(empty_res["attempted"])
        self.assertFalse(empty_res["crashed"])
        self.assertIsNone(empty_res["witness_sha256"])

        missing_res = verify_live_crash("/nonexistent/binary_path_xyz", b"AAAA")
        self.assertFalse(missing_res["attempted"])
        self.assertFalse(missing_res["crashed"])

        from unittest.mock import patch
        import subprocess

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=BINARY_PATH, timeout=0.05)):
            t_res = verify_live_crash(BINARY_PATH, b"AAAA", timeout_s=0.05)
            self.assertTrue(t_res["attempted"])
            self.assertFalse(t_res["crashed"])
            self.assertFalse(t_res["expected_vuln_crash"])
            self.assertTrue(t_res["timed_out"])


class TestSchedulerComparison(unittest.TestCase):
    """Phase 2 Req 4 & 6: Reproducible DFS baseline vs MaxHeap risk-prioritized scheduler comparison."""

    def test_dfs_baseline_reproducibility(self):
        p1 = AnalysisBackendProvider(BINARY_PATH, max_steps=35, scheduler_mode="dfs")
        t1 = [s.instruction_address for s in p1.get_execution_trace()]

        p2 = AnalysisBackendProvider(BINARY_PATH, max_steps=35, scheduler_mode="dfs")
        t2 = [s.instruction_address for s in p2.get_execution_trace()]

        self.assertEqual(t1, t2)
        self.assertEqual(p1.scheduler_telemetry["states_explored"], p2.scheduler_telemetry["states_explored"])

    def test_maxheap_prioritizes_deep_target_over_dfs_under_identical_budget(self):
        # Single-binary demonstration on test_benchmarks_binary:
        # trigger_double_free (0x100000624) is the 5th branch in main().
        # Both modes receive identical binary input, step budget (38), timeout (10.0s), and symbolic input size (32).
        target_addr = 0x100000624
        shared_budget = 38
        shared_timeout = 10.0
        shared_sym_size = 32

        p_dfs = AnalysisBackendProvider(
            BINARY_PATH,
            max_steps=shared_budget,
            timeout_seconds=shared_timeout,
            symbolic_input_size=shared_sym_size,
            scheduler_mode="dfs",
            gnn_node_scores={target_addr: 0.95},
        )
        vulns_dfs = p_dfs.scan_vulnerabilities()
        dfs_types = {v["vuln_type"] for v in vulns_dfs}
        self.assertNotIn("DOUBLE_FREE", dfs_types)

        p_heap = AnalysisBackendProvider(
            BINARY_PATH,
            max_steps=shared_budget,
            timeout_seconds=shared_timeout,
            symbolic_input_size=shared_sym_size,
            scheduler_mode="maxheap",
            gnn_node_scores={target_addr: 0.95},
        )
        vulns_heap = p_heap.scan_vulnerabilities()
        heap_df = [v for v in vulns_heap if v["vuln_type"] == "DOUBLE_FREE"]
        self.assertEqual(len(heap_df), 1)
        self.assertEqual(heap_df[0]["solver_status"], "SAT")
        self.assertTrue(heap_df[0]["exploit_verified"])
        self.assertEqual(heap_df[0]["input_channel"], "stdin")
        self.assertTrue(bytes(heap_df[0]["crash_integers"]).startswith(b"double\x00"))

        # Confirm priority scores are actually computed from the intended GNN risk value (0.95 - 0.02 * depth)
        popped = p_heap.scheduler_telemetry.get("popped_priorities", [])
        self.assertGreater(len(popped), 0)
        self.assertAlmostEqual(popped[0]["reachable_risk"], 0.95, places=5)
        self.assertAlmostEqual(popped[0]["priority"], 0.95 - 0.02 * popped[0]["depth"], places=5)
        for item in popped:
            expected_p = round(item["reachable_risk"] - p_heap.depth_penalty_lambda * item["depth"], 6)
            self.assertAlmostEqual(item["priority"], expected_p, places=5)


if __name__ == "__main__":
    unittest.main()
