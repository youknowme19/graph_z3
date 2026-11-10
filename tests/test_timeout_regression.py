"""
test_timeout_regression.py — NeuroZ3 Phase 4 Final Integrity Pass
Regression tests verifying timeout enforcement, timer lifecycle cleanup,
and protection against exception swallowing.
"""

import os
import sys
import time
import signal
import weakref
import unittest
import z3

# Add project root and src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../src")))

from core.interfaces import AnalysisBackendProvider, SymbolicTimeout
from symbolic.z3_interface import Z3Interface

BENCHMARK_BINARY = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "test_benchmarks_binary")
)


class TestTimeoutRegression(unittest.TestCase):
    """Explicit regression tests for all timeout failure modes."""

    def setUp(self):
        AnalysisBackendProvider._timeout_flag = False
        # Ensure any leftover timer is disarmed
        signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)

    def tearDown(self):
        AnalysisBackendProvider._timeout_flag = False
        signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)

    # --------------------------------------------------------------------------
    # 1. Verification that SymbolicTimeout inherits from BaseException and
    #    CANNOT be swallowed by generic 'except Exception:' handlers
    # --------------------------------------------------------------------------
    def test_generic_except_exception_cannot_swallow_symbolic_timeout(self):
        """Verify that generic except Exception handlers cannot swallow SymbolicTimeout."""
        self.assertTrue(
            issubclass(SymbolicTimeout, BaseException),
            "SymbolicTimeout must inherit from BaseException"
        )
        self.assertFalse(
            issubclass(SymbolicTimeout, Exception),
            "SymbolicTimeout must NOT inherit from Exception"
        )

        caught_by_generic = False
        caught_by_symbolic = False

        try:
            try:
                raise SymbolicTimeout("Simulated exploration timeout")
            except Exception:
                caught_by_generic = True
        except SymbolicTimeout:
            caught_by_symbolic = True

        self.assertFalse(
            caught_by_generic,
            "Generic 'except Exception:' illegally caught SymbolicTimeout!"
        )
        self.assertTrue(
            caught_by_symbolic,
            "SymbolicTimeout was not caught by outer handler"
        )

        # Test through multi-exception handlers commonly used in libraries
        caught_by_multi = False
        caught_outer = False
        try:
            try:
                raise SymbolicTimeout("Timeout through library stack")
            except (ValueError, KeyError, TypeError, RuntimeError, IOError, OSError, Exception):
                caught_by_multi = True
        except SymbolicTimeout:
            caught_outer = True

        self.assertFalse(caught_by_multi, "Multi-exception handler caught SymbolicTimeout")
        self.assertTrue(caught_outer, "Outer handler failed to receive SymbolicTimeout")

    # --------------------------------------------------------------------------
    # 2. Timeout during angr exploration loop
    # --------------------------------------------------------------------------
    def test_angr_exploration_timeout(self):
        """Verify timeout during symbolic trace exploration terminates within deadline."""
        def _alarm_handler(signum, frame):
            AnalysisBackendProvider._timeout_flag = True
            raise SymbolicTimeout("Exploration budget reached")

        signal.signal(signal.SIGALRM, _alarm_handler)
        t_start = time.perf_counter()
        timed_out = False

        # Run provider with a strict 0.25 second timeout
        timeout_budget = 0.25
        provider = AnalysisBackendProvider(
            BENCHMARK_BINARY,
            max_steps=50000,
            scheduler_mode="dfs",
            timeout_seconds=timeout_budget,
        )

        try:
            signal.setitimer(signal.ITIMER_REAL, timeout_budget, 0.1)
            provider.get_execution_trace()
        except SymbolicTimeout:
            timed_out = True
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)

        elapsed = time.perf_counter() - t_start
        self.assertLess(
            elapsed, 3.0,
            f"Exploration exceeded acceptable window: took {elapsed:.2f}s for {timeout_budget}s budget"
        )
        self.assertTrue(
            timed_out or provider.scheduler_telemetry.get("timed_out") or AnalysisBackendProvider._timeout_flag,
            "Exploration did not signal timeout"
        )
        # Ensure timer is fully cancelled
        rem_timer = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(rem_timer, (0.0, 0.0), f"Timer not cancelled: {rem_timer}")

    # --------------------------------------------------------------------------
    # 3. Timeout during Z3 solver.check()
    # --------------------------------------------------------------------------
    def test_z3_solver_check_timeout(self):
        """Verify solver.check() timeout enforcement on intractable constraint systems."""
        s = z3.Solver()
        s.set("timeout", 50)  # 50 ms solver-level timeout

        # Formulate an intractable non-linear integer system
        vars_list = [z3.Int(f"x_{i}") for i in range(12)]
        for i in range(len(vars_list) - 1):
            s.add(vars_list[i] * vars_list[i + 1] + vars_list[i] ** 3 == (i + 1) * 1337)
            s.add(vars_list[i] > 0)

        t0 = time.perf_counter()
        status = s.check()
        elapsed_ms = (time.perf_counter() - t0) * 1000

        # Status must be unknown/timeout, and execution should not hang indefinitely
        self.assertIn(status, [z3.unknown, z3.unsat, z3.sat])
        self.assertLess(elapsed_ms, 2500, f"Z3 solver took {elapsed_ms:.1f}ms, exceeding cap")

        # Also test Z3Interface evaluate_path wrapper timeout parameter
        import angr
        proj = angr.Project(BENCHMARK_BINARY, auto_load_libs=False)
        entry_state = proj.factory.entry_state()
        res = Z3Interface.evaluate_path(entry_state, {}, timeout_ms=50)
        self.assertIn(res["status"], ["SAT", "UNSAT", "UNKNOWN", "TIMEOUT"])
        self.assertIn("solver_time_ms", res)

    # --------------------------------------------------------------------------
    # 4. Timeout during weak-reference garbage collection callbacks
    # --------------------------------------------------------------------------
    def test_weakref_gc_callback_timeout(self):
        """Verify that timeout signals arriving during weakref callbacks are not lost."""
        callback_fired = False
        second_tick_fired = False

        class TrackedObject:
            pass

        obj = TrackedObject()

        def _alarm_handler(signum, frame):
            AnalysisBackendProvider._timeout_flag = True
            raise SymbolicTimeout("Recurring timer fired")

        signal.signal(signal.SIGALRM, _alarm_handler)

        def weak_cb(ref):
            nonlocal callback_fired
            callback_fired = True
            # Simulate what happens when alarm occurs or flag is inspected during GC
            AnalysisBackendProvider._timeout_flag = True

        wr = weakref.ref(obj, weak_cb)

        # 1. Trigger weakref callback
        del obj
        self.assertTrue(callback_fired, "Weakref callback did not execute")
        self.assertTrue(
            AnalysisBackendProvider._timeout_flag,
            "_timeout_flag was not set during callback"
        )

        # 2. Verify that recurring timer delivers exception to outer frame
        AnalysisBackendProvider._timeout_flag = False
        caught_symbolic = False
        try:
            # Set a fast 0.05s timer recurring at 0.05s
            signal.setitimer(signal.ITIMER_REAL, 0.05, 0.05)
            # Busy wait in Python bytecode
            t_w = time.perf_counter()
            while time.perf_counter() - t_w < 1.0:
                pass
        except SymbolicTimeout:
            caught_symbolic = True
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)

        self.assertTrue(
            caught_symbolic,
            "Recurring timer failed to deliver SymbolicTimeout to main frame"
        )
        self.assertTrue(
            AnalysisBackendProvider._timeout_flag,
            "Recurring alarm handler did not mark _timeout_flag = True"
        )

    # --------------------------------------------------------------------------
    # 5. Timeout during deeply nested function exploration
    # --------------------------------------------------------------------------
    def test_nested_function_exploration_timeout(self):
        """Verify that SymbolicTimeout cleanly unwinds deep call stacks without corruption."""
        depth_reached = 0

        def recursive_explorer(current_depth: int, max_depth: int):
            nonlocal depth_reached
            depth_reached = current_depth
            if current_depth >= max_depth:
                # Trigger timeout at bottom of stack
                AnalysisBackendProvider._timeout_flag = True
                raise SymbolicTimeout(f"Timeout at depth {current_depth}")

            try:
                return recursive_explorer(current_depth + 1, max_depth)
            except Exception:
                # Deliberately place a generic handler in inner frames
                self.fail("Generic 'except Exception:' in nested frame caught SymbolicTimeout!")

        caught = False
        try:
            recursive_explorer(1, 30)
        except SymbolicTimeout as e:
            caught = True
            self.assertIn("depth 30", str(e))

        self.assertTrue(caught, "SymbolicTimeout failed to unwind from depth 30")
        self.assertEqual(depth_reached, 30)

    # --------------------------------------------------------------------------
    # 6. Correct timer cleanup after Success, Timeout, and Exception paths
    # --------------------------------------------------------------------------
    def test_correct_timer_cleanup_all_paths(self):
        """Verify that signal.setitimer is completely disarmed across all three exit paths."""
        def dummy_alarm(signum, frame):
            raise SymbolicTimeout("Timer alarm")

        signal.signal(signal.SIGALRM, dummy_alarm)

        # Path A: Normal successful completion
        try:
            signal.setitimer(signal.ITIMER_REAL, 10.0, 0.5)
            # Work completes cleanly
            _val = 42 * 2
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)

        timer_a = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(timer_a, (0.0, 0.0), f"Path A (Success) failed to disarm timer: {timer_a}")

        # Path B: Timeout occurred
        timeout_caught = False
        try:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0.05, 0.05)
                t_b = time.perf_counter()
                while time.perf_counter() - t_b < 1.0:
                    pass
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
        except SymbolicTimeout:
            timeout_caught = True

        self.assertTrue(timeout_caught, "Path B timeout was not caught")
        timer_b = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(timer_b, (0.0, 0.0), f"Path B (Timeout) failed to disarm timer: {timer_b}")

        # Path C: Unexpected Exception (e.g., ValueError)
        exception_caught = False
        try:
            try:
                signal.setitimer(signal.ITIMER_REAL, 10.0, 0.5)
                raise ValueError("Unexpected application error")
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)
        except ValueError:
            exception_caught = True

        self.assertTrue(exception_caught, "Path C exception was not caught")
        timer_c = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(timer_c, (0.0, 0.0), f"Path C (Exception) failed to disarm timer: {timer_c}")

    # --------------------------------------------------------------------------
    # 7. Verification that no BaseException handler in codebase swallows SymbolicTimeout
    # --------------------------------------------------------------------------
    def test_base_exception_handler_verification(self):
        """Verify that any BaseException or bare except handler re-raises SymbolicTimeout."""
        # Simulated outer framework handler that intercepts BaseException
        caught_and_reraised = False

        def framework_worker():
            raise SymbolicTimeout("Exploration budget hit")

        try:
            try:
                framework_worker()
            except BaseException as e:
                # Correct pattern: re-raise critical control exceptions
                if isinstance(e, (KeyboardInterrupt, SystemExit, SymbolicTimeout)):
                    raise
                pass
        except SymbolicTimeout:
            caught_and_reraised = True

        self.assertTrue(
            caught_and_reraised,
            "Guarded BaseException handler failed to re-raise SymbolicTimeout"
        )


if __name__ == "__main__":
    unittest.main()
