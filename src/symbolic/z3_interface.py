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
        extra_constraints: Optional[List[Any]] = None,
        timeout_ms: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates the accumulated path constraints of a given execution state dynamically
        using the raw Z3 Solver API.
        
        :param state: The current angr SimState containing real path constraints.
        :param symbolic_variables: A dictionary mapping names to claripy.BVS symbolic variables.
        :param parent_solver: The Z3 Solver from the parent state (if any) to clone.
        :param parent_constraints: The list of constraints from the parent state.
        :param extra_constraints: Optional list of raw claripy AST constraints to append.
        :param timeout_ms: Optional solver timeout in milliseconds (overrides Z3_TIMEOUT_MS).
        :return: A dictionary containing SAT/UNSAT/UNKNOWN/TIMEOUT/ERROR status, model, Z3 solver, and statistics.
        """
        import time
        import os as _os
        t0 = time.perf_counter()

        if state is None or not hasattr(state, "solver"):
            return {
                'status': 'ERROR',
                'error': 'Invalid or missing symbolic state',
                'constraints_evaluated': [],
                'satisfying_assignment': {},
                'solver_time_ms': 0.0,
                'queries_count': 0,
                'z3_statistics': 'N/A',
                'solver_obj': None,
            }

        try:
            # 1. Initialize or clone solver (only reuse parent_solver when no extra_constraints are mutated)
            if parent_solver is not None and not extra_constraints:
                try:
                    solver = parent_solver.translate(z3.main_ctx())
                except Exception:
                    solver = z3.Solver()
                    parent_constraints = None
            else:
                solver = z3.Solver()
                parent_constraints = None

            # Apply a timeout so a complex constraint set cannot hang indefinitely.
            _timeout_ms = int(timeout_ms if timeout_ms is not None else _os.environ.get("Z3_TIMEOUT_MS", "30000"))
            solver.set("timeout", max(1, _timeout_ms))

            # 2. Extract target variables for slicing
            target_var_names = set()
            for v in (symbolic_variables or {}).values():
                if hasattr(v, "variables"):
                    target_var_names.update(v.variables)

            # 3. Slice constraints (including extra constraints if provided)
            all_constraints = list(state.solver.constraints)
            if extra_constraints:
                all_constraints.extend(extra_constraints)

            if extra_constraints:
                for ec in extra_constraints:
                    if hasattr(ec, "variables"):
                        target_var_names.update(ec.variables)

            sliced_constraints = Z3Interface.slice_constraints(all_constraints, target_var_names)

            # 4. Add constraints to solver (only new ones if parent solver is cloned)
            parent_hashes = set(hash(c) for c in parent_constraints) if parent_constraints else set()
            z3_constraints = []

            for c in sliced_constraints:
                if hash(c) in parent_hashes:
                    continue  # already in the cloned solver
                z3_c = claripy.backends.z3.convert(c)
                solver.add(z3_c)
                z3_constraints.append(str(z3_c))

            # 5. Check satisfiability
            check_result = solver.check()
            is_sat = (check_result == z3.sat)
            is_unknown = (check_result == z3.unknown)
            solver_time_ms = round((time.perf_counter() - t0) * 1000, 2)

            z3_model = None
            if is_unknown:
                reason = ""
                try:
                    reason = str(solver.reason_unknown() or "").lower()
                except Exception:
                    pass
                if "timeout" in reason or "canceled" in reason or solver_time_ms >= (_timeout_ms * 0.85):
                    status = "TIMEOUT"
                else:
                    status = "UNKNOWN"
            elif is_sat:
                status = "SAT"
                # Witness beautification: try constraining symbolic inputs to printable ASCII inside a temporary scope
                beautify_constraints = []
                try:
                    for name, sym_var in (symbolic_variables or {}).items():
                        if not hasattr(sym_var, "size"):
                            continue
                        z3_var = claripy.backends.z3.convert(sym_var)
                        if not z3.is_bv(z3_var):
                            continue
                        size_bytes = sym_var.size() // 8
                        for i in range(size_bytes):
                            byte_expr = z3.Extract((i + 1) * 8 - 1, i * 8, z3_var)
                            beautify_constraints.append(z3.And(byte_expr >= 0x20, byte_expr <= 0x7e))
                except Exception:
                    beautify_constraints = []

                if beautify_constraints:
                    solver.push()
                    try:
                        solver.add(beautify_constraints)
                        if solver.check() == z3.sat:
                            z3_model = solver.model()
                    except Exception:
                        z3_model = None
                    finally:
                        try:
                            solver.pop()
                        except Exception:
                            pass

                if z3_model is None:
                    try:
                        if solver.check() == z3.sat:
                            z3_model = solver.model()
                    except Exception:
                        z3_model = None
            else:
                status = "UNSAT"

            # Gather Z3 statistics
            z3_stats = solver.statistics()
            stats_str = str(z3_stats)

            result = {
                'status': status,
                'constraints_evaluated': z3_constraints if z3_constraints else [str(c) for c in all_constraints],
                'satisfying_assignment': {},
                'solver_time_ms': solver_time_ms,
                'queries_count': len(all_constraints),
                'z3_statistics': stats_str,
                'solver_obj': solver if (is_sat and not extra_constraints) else None,
            }

            # If satisfiable, extract values from the Z3 model
            if is_sat and symbolic_variables:
                if z3_model is None:
                    try:
                        if solver.check() == z3.sat:
                            z3_model = solver.model()
                    except Exception:
                        z3_model = None
                for name, sym_var in symbolic_variables.items():
                    try:
                        if z3_model is not None:
                            z3_var = claripy.backends.z3.convert(sym_var)
                            z3_val = z3_model.eval(z3_var, model_completion=True)
                            if z3.is_bv_value(z3_val):
                                val_int = z3_val.as_long()
                                size_bytes = max(1, sym_var.size() // 8)
                                concrete_value = val_int.to_bytes(size_bytes, byteorder='big')
                                result['satisfying_assignment'][name] = concrete_value
                                continue
                        result['satisfying_assignment'][name] = state.solver.eval(
                            sym_var, cast_to=bytes, extra_constraints=extra_constraints
                        )
                    except Exception as e:
                        result['satisfying_assignment'][name] = f"<Evaluation Error: {str(e)}>"

            return result
        except Exception as e:
            solver_time_ms = round((time.perf_counter() - t0) * 1000, 2)
            return {
                'status': 'ERROR',
                'error': str(e),
                'constraints_evaluated': [],
                'satisfying_assignment': {},
                'solver_time_ms': solver_time_ms,
                'queries_count': 0,
                'z3_statistics': 'N/A',
                'solver_obj': None,
            }
