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
            
        sliced_constraints = Z3Interface.slice_constraints(all_constraints, target_var_names)

        # 4. Add constraints to solver (only new ones if parent solver is cloned)
        parent_hashes = set(hash(c) for c in parent_constraints) if parent_constraints else set()
        z3_constraints = []
        
        for c in sliced_constraints:
            if hash(c) in parent_hashes:
                continue  # already in the cloned solver
            try:
                z3_c = claripy.backends.z3.convert(c)
                solver.add(z3_c)
                z3_constraints.append(str(z3_c))
            except Exception:
                pass

        # 5. Check satisfiability
        check_result = solver.check()
        is_sat = (check_result == z3.sat)
        is_timeout = (check_result == z3.unknown)
        solver_time_ms = round((time.perf_counter() - t0) * 1000, 2)

        if is_timeout:
            status = "TIMEOUT"
        elif is_sat:
            status = "SAT"
            
            # Witness beautification: try constraining symbolic inputs to printable ASCII
            solver.push()
            try:
                beautify_constraints = []
                for name, sym_var in symbolic_variables.items():
                    z3_var = claripy.backends.z3.convert(sym_var)
                    size_bytes = sym_var.size() // 8
                    for i in range(size_bytes):
                        byte_expr = z3.Extract((i + 1) * 8 - 1, i * 8, z3_var)
                        beautify_constraints.append(z3.And(byte_expr >= 0x20, byte_expr <= 0x7e))
                solver.add(beautify_constraints)
                if solver.check() != z3.sat:
                    solver.pop()  # Too restrictive, revert to original SAT model
                    solver.check()
            except Exception:
                try:
                    solver.pop()
                    solver.check()
                except Exception:
                    pass
        else:
            status = "UNSAT"

        # Gather Z3 statistics
        z3_stats = solver.statistics()
        stats_str = str(z3_stats)

        result = {
            'status': status,
            'constraints_evaluated': z3_constraints if z3_constraints else [str(c) for c in state.solver.constraints],
            'satisfying_assignment': {},
            'solver_time_ms': solver_time_ms,
            'queries_count': len(state.solver.constraints),
            'z3_statistics': stats_str,
            'solver_obj': solver,  # cache for next step
        }

        # If satisfiable, extract values from the raw Z3 model
        if is_sat and symbolic_variables:
            try:
                z3_model = solver.model()
                for name, sym_var in symbolic_variables.items():
                    try:
                        z3_var = claripy.backends.z3.convert(sym_var)
                        z3_val = z3_model.eval(z3_var)
                        
                        if z3.is_bv_value(z3_val):
                            val_int = z3_val.as_long()
                            size_bytes = sym_var.size() // 8
                            concrete_value = val_int.to_bytes(size_bytes, byteorder='big')
                            result['satisfying_assignment'][name] = concrete_value
                        else:
                            result['satisfying_assignment'][name] = state.solver.eval(sym_var, cast_to=bytes)
                    except Exception:
                        try:
                            result['satisfying_assignment'][name] = state.solver.eval(sym_var, cast_to=bytes)
                        except Exception as e:
                            result['satisfying_assignment'][name] = f"<Evaluation Error: {str(e)}>"
            except Exception:
                # Fallback to angr's native solver if Z3 model retrieval fails
                for name, sym_var in symbolic_variables.items():
                    try:
                        result['satisfying_assignment'][name] = state.solver.eval(sym_var, cast_to=bytes)
                    except Exception as e:
                        result['satisfying_assignment'][name] = f"<Evaluation Error: {str(e)}>"

        return result
