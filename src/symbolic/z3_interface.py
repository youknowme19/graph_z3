import z3
import claripy
from typing import Dict, List, Any, Optional, Set

class Z3Interface:
    """
    Evaluates symbolic constraints using the Z3 SMT solver.
    Supports incremental solving (cloning parent solvers) and constraint slicing.
    """

    @staticmethod
    def slice_constraints(constraints: List[Any], target_vars: Set[str]) -> List[Any]:
        """
        Slices and returns only the constraints that transitively affect the target variables.
        Constant constraints (with no variables) are always preserved.
        """
        if not target_vars:
            return list(constraints)

        relevant_vars = set(target_vars)
        sliced = []
        remaining_constraints = []

        # Separate constant constraints and variable constraints
        for c in constraints:
            if not getattr(c, "variables", None):
                sliced.append(c)
            else:
                remaining_constraints.append(c)

        # Fixed-point iteration for transitive closure
        added = True
        while added:
            added = False
            next_remaining = []
            for c in remaining_constraints:
                c_vars = c.variables
                if c_vars & relevant_vars:
                    sliced.append(c)
                    relevant_vars.update(c_vars)
                    added = True
                else:
                    next_remaining.append(c)
            remaining_constraints = next_remaining

        return sliced

    @staticmethod
    def evaluate_path(
        state: Any,
        symbolic_variables: Dict[str, Any],
        parent_solver: Optional[z3.Solver] = None,
        parent_constraints: Optional[List[Any]] = None,
        extra_constraints: Optional[List[Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates the accumulated path constraints of a given execution state dynamically
        using the raw Z3 Solver API.
        
        :param state: The current angr SimState containing real path constraints.
        :param symbolic_variables: A dictionary mapping names to claripy.BVS symbolic variables.
        :param parent_solver: The Z3 Solver from the parent state (if any) to clone.
        :param parent_constraints: The list of constraints from the parent state.
        :param extra_constraints: Optional list of raw claripy AST constraints to append.
        :return: A dictionary containing SAT/UNSAT status, the satisfying mathematical model, Z3 solver, and statistics.
        """
        import time
        t0 = time.perf_counter()

        # 1. Initialize or clone solver
        if parent_solver is not None:
            try:
                solver = parent_solver.translate(z3.main_ctx())
            except Exception:
                solver = z3.Solver()
        else:
            solver = z3.Solver()

        # Apply a timeout so a complex constraint set cannot hang indefinitely.
        # Default: 30 s. Override via Z3_TIMEOUT_MS environment variable.
        import os as _os
        _timeout_ms = int(_os.environ.get("Z3_TIMEOUT_MS", "30000"))
        solver.set("timeout", _timeout_ms)

        # 2. Extract target variables for slicing
        target_var_names = set()
        for v in symbolic_variables.values():
            if hasattr(v, "variables"):
                target_var_names.update(v.variables)

        # 3. Slice constraints (including extra constraints if provided)
        all_constraints = list(state.solver.constraints)
        if extra_constraints:
            all_constraints.extend(extra_constraints)
