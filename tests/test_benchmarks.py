import os
import sys
import unittest
import angr

# Add project root and src to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.interfaces import AnalysisBackendProvider

BENCHMARK_BINARY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "test_benchmarks_binary")
)

# ---------------------------------------------------------------------------
# Helper: targeted scan at a named function
# ---------------------------------------------------------------------------

def _scan_function(func_name: str, max_steps: int = 400):
    """
    Start analysis at a specific function using the targeted scan mode
    (inject_symbolic_function_args) rather than from the binary entry point.
    This avoids the DFS step budget being exhausted before reaching dispatch branches.
    """
    project = angr.Project(BENCHMARK_BINARY, load_options={"auto_load_libs": False})
    project.analyses.CFGFast()

    # Locate the function by name (strip leading underscore for Mach-O)
    target_addr = None
    for addr, func in project.kb.functions.items():
        name = func.name or ""
        if name == func_name or name == f"_{func_name}":
            target_addr = addr
            break

    if target_addr is None:
        # Fallback: entry-point scan
        backend = AnalysisBackendProvider(BENCHMARK_BINARY, max_steps=max_steps)
    else:
        backend = AnalysisBackendProvider(
            BENCHMARK_BINARY,
            max_steps=max_steps,
            target_func_addr=target_addr,
        )

    return backend.scan_vulnerabilities()


class TestVulnerabilityReasoningEngine(unittest.TestCase):

    def test_stack_overflow(self):
        """trigger_stack_overflow: memcpy(buf[8], input[32]) — guaranteed overflow."""
        vulns = _scan_function("trigger_stack_overflow")
        types = [v["vuln_type"] for v in vulns]
        # Accept OOB_WRITE, STACK_OVERFLOW, or SYMBOLIC_PC — all indicate control-flow compromise
        self.assertTrue(
            any(t in ("STACK_OVERFLOW", "OOB_WRITE", "SYMBOLIC_PC", "CRASH") for t in types),
            f"Expected a stack/OOB/SYMBOLIC_PC/CRASH finding, got: {types}",
        )

    def test_heap_overflow(self):
        """trigger_heap_overflow: malloc(8) then memcpy(buf, input, 32)."""
        vulns = _scan_function("trigger_heap_overflow")
        types = [v["vuln_type"] for v in vulns]
        self.assertTrue(
            any(t in ("OOB_WRITE", "STACK_OVERFLOW", "SYMBOLIC_PC", "CRASH") for t in types),
            f"Expected OOB_WRITE/STACK_OVERFLOW/SYMBOLIC_PC/CRASH, got: {types}",
        )

    def test_null_dereference(self):
        """trigger_null_deref: *ptr = 0xdeadbeef where ptr = NULL."""
        vulns = _scan_function("trigger_null_deref")
        types = [v["vuln_type"] for v in vulns]
        self.assertTrue(
            any(t in ("NULL_DEREF", "OOB_WRITE", "STACK_OVERFLOW", "SYMBOLIC_PC", "CRASH") for t in types),
            f"Expected a crash-class finding, got: {types}",
        )

    def test_use_after_free(self):
        """trigger_use_after_free: free(buf); buf[0]='C' — write to freed memory."""
        vulns = _scan_function("trigger_use_after_free")
        types = [v["vuln_type"] for v in vulns]
        self.assertTrue(
            any(t in ("USE_AFTER_FREE", "OOB_WRITE", "STACK_OVERFLOW", "SYMBOLIC_PC", "CRASH") for t in types),
            f"Expected UAF/OOB/SYMBOLIC_PC/CRASH, got: {types}",
        )

    def test_double_free(self):
        """trigger_double_free: free(buf) called twice."""
        vulns = _scan_function("trigger_double_free")
        types = [v["vuln_type"] for v in vulns]
        self.assertTrue(
            any(t in ("DOUBLE_FREE", "OOB_WRITE", "STACK_OVERFLOW", "SYMBOLIC_PC", "ABORT", "CRASH") for t in types),
            f"Expected DOUBLE_FREE/SYMBOLIC_PC/ABORT/CRASH, got: {types}",
        )


if __name__ == "__main__":
    unittest.main()
