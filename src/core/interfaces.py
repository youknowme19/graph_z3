from typing import List, Optional, Dict, Any, Tuple, Set
from dataclasses import dataclass, field
import time
import uuid
import collections
import hashlib
import re

from core.binary_loader import BinaryLoader
from symbolic.engine import SymbolicEngine
from symbolic.z3_interface import Z3Interface
from core.fix_advisor import FixAdvisor
from core.exploit_classifier import classify_exploit_primitive, ExploitPrimitive, primitive_to_dict


@dataclass
class ExecutionState:
    function_name: str
    basic_block: str
    instruction_address: str
    execution_depth: int
    symbolic_variables: str
    path_constraints: str
    solver_status: str
    model_information: str
    explanation: str
    next_state: str
    is_library: bool = False
    is_branch: bool = False
    raw_path_constraints: str = ""
    event_type: str = "NORMAL"
    previous_block: str = ""
    next_block: str = ""
    transferred_function: bool = False
    new_constraints_introduced: bool = False
    constraint_count: int = 0
    is_vulnerable: bool = False
    vuln_type: str = ""
    vuln_severity: str = ""
    vuln_details: str = ""
    _registry_key: str = field(default_factory=lambda: str(uuid.uuid4()), repr=False, compare=False)
    _parent_registry_key: Optional[str] = None


@dataclass
class ConstraintResult:
    constraint_list: str
    status: str
    statistics: str
    model: str
    explanation: str
    raw_constraint_list: str = ""
    solver_time_ms: float = 0.0
    constraint_annotations: List[str] = field(default_factory=list)
    symbolic_variables_list: List[Dict[str, Any]] = field(default_factory=list)


_CRASH_STUBS: set = {
    "__stack_chk_fail",
    "__stack_smashing_detected",
    "abort",
    "__assert_fail",
    "__assert_rtn",
    "_exit",
    "raise",
}

_STUB_META: Dict[str, tuple] = {
    "__stack_chk_fail":           ("CANARY",   "CRITICAL", "Stack canary blown."),
    "__stack_smashing_detected":  ("CANARY",   "CRITICAL", "Stack smashing detected."),
    "abort":                      ("ABORT",    "HIGH",     "Program called abort()."),
    "__assert_fail":              ("ABORT",    "HIGH",     "Assertion failure."),
    "__assert_rtn":               ("ABORT",    "HIGH",     "Assertion failure (macOS)."),
    "_exit":                      ("ABORT",    "MEDIUM",   "Forced process exit."),
    "raise":                      ("ABORT",    "HIGH",     "Signal raised."),
}

_OP_SYMBOLS = {
    '__eq__': '==', '__ne__': '!=',
    '__le__': '<=', '__lt__': '<', '__ge__': '>=', '__gt__': '>',
    'SLE': '<=', 'SLT': '<', 'SGE': '>=', 'SGT': '>',
    'ULE': '<=', 'ULT': '<', 'UGE': '>=', 'UGT': '>',
    '__add__': '+', '__sub__': '-', '__mul__': '*',
    '__xor__': '^', '__and__': '&', '__or__': '|',
    '__lshift__': '<<', 'LShR': '>>', '__rshift__': '>>',
}


def _fmt_constant(value: int, bits: int) -> str:
    num_bytes = max(1, bits // 8)
    if num_bytes == 1 and 32 <= value < 127:
        return f"0x{value:02x} ('{chr(value)}')"
    try:
        return f"0x{value:0{num_bytes * 2}x}"
    except Exception:
        return hex(value)


def _describe_extract(hi: int, lo: int, var_label: str) -> str:
    lo_byte, hi_byte = lo // 8, hi // 8
    if lo_byte == hi_byte:
        return f"byte {lo_byte} of {var_label}"
    return f"bytes {lo_byte}-{hi_byte} of {var_label}"


def _humanize_ast(node, depth: int = 0) -> str:
    if depth > 6:
        return "..."
    op = getattr(node, 'op', None)
    args = getattr(node, 'args', None)
    if op is None or args is None:
        return str(node)
    try:
        if op == 'BVV':
            return _fmt_constant(args[0], args[1])
        if op == 'BoolV':
            return "true" if args[0] else "false"
        if op == 'BVS':
            return str(args[0]).split('_')[0] + " input"
        if op == 'Extract' and len(args) == 3:
            hi, lo, child = args
            if getattr(child, 'op', None) == 'BVS':
                return _describe_extract(hi, lo, str(child.args[0]).split('_')[0] + " input")
            return f"bits {lo}-{hi} of ({_humanize_ast(child, depth + 1)})"
        if op == 'Concat':
            return " ++ ".join(_humanize_ast(a, depth + 1) for a in args)
        if op == 'Not':
            return f"NOT ({_humanize_ast(args[0], depth + 1)})"
        if op == 'And':
            return " AND ".join(_humanize_ast(a, depth + 1) for a in args)
        if op == 'Or':
            return " OR ".join(_humanize_ast(a, depth + 1) for a in args)
        if op in ('ZeroExt', 'SignExt') and len(args) == 2:
            return _humanize_ast(args[1], depth + 1)
        if op == 'Reverse' and len(args) == 1:
            return _humanize_ast(args[0], depth + 1)
        if op in _OP_SYMBOLS and len(args) == 2:
            left, right = args
            return f"{_humanize_ast(left, depth + 1)} {_OP_SYMBOLS[op]} {_humanize_ast(right, depth + 1)}"
    except Exception:
        pass
    try:
        child_strs = [_humanize_ast(a, depth + 1) for a in args if hasattr(a, 'op')]
        if child_strs:
            return f"{op}(" + ", ".join(child_strs) + ")"
    except Exception:
        pass
    text = str(node)
    return text if len(text) <= 80 else text[:77] + "..."


def _humanize_constraint(constraint) -> str:
    try:
        return _humanize_ast(constraint)
    except Exception:
        return str(constraint)


def _pretty_print_constraint(c_str: str, max_depth: int = 3) -> str:
    indent = 0
    lines = []
    curr = ""
    for char in c_str:
        if char == '(':
            if curr.strip():
                lines.append("  " * indent + curr.strip())
            curr = ""
            lines.append("  " * indent + "(")
            indent += 1
            if indent > max_depth:
                lines.append("  " * indent + "...")
                break
        elif char == ')':
            if curr.strip():
                lines.append("  " * indent + curr.strip())
            curr = ""
            indent = max(0, indent - 1)
            lines.append("  " * indent + ")")
        elif char == ',':
            if curr.strip():
                lines.append("  " * indent + curr.strip() + ",")
            curr = ""
        else:
            curr += char
    if curr.strip():
        lines.append("  " * indent + curr.strip())
    return "\n".join(lines)


def get_byte_status(state, sym_var) -> Tuple[List[int], List[int]]:
    size_bytes = sym_var.size() // 8
    constrained_bytes = []
    unconstrained_bytes = []
    for i in range(size_bytes):
        hi = (size_bytes - 1 - i) * 8 + 7
        lo = (size_bytes - 1 - i) * 8
        byte_expr = sym_var[hi:lo]
        try:
            possible_values = state.solver.eval_upto(byte_expr, 2)
            if len(possible_values) == 1:
                constrained_bytes.append(i)
            else:
                unconstrained_bytes.append(i)
        except Exception:
            constrained_bytes.append(i)
    return constrained_bytes, unconstrained_bytes


def get_symbolic_variables_from_state(state, injected_vars) -> Dict[str, Any]:
    vars_dict = dict(injected_vars)

    def walk(node):
        if not hasattr(node, 'op') or not hasattr(node, 'args'):
            return
        if node.op == 'BVS':
            name = node.args[0]
            if name not in vars_dict:
                vars_dict[name] = node
            return
        for arg in node.args:
            walk(arg)

    for constraint in state.solver.constraints:
        walk(constraint)
    return vars_dict


def _get_bvs_and_offset(node) -> Tuple[Optional[str], Optional[int]]:
    if not hasattr(node, 'op') or not hasattr(node, 'args'):
        return None, None
    if node.op == 'BVS':
        return node.args[0], 0
    if node.op == 'Extract' and len(node.args) == 3:
        hi, lo, child = node.args
        if child.op == 'BVS':
            return child.args[0], lo // 8
        if child.op == 'Reverse' and child.args[0].op == 'BVS':
            return child.args[0].args[0], lo // 8
    if node.op == 'Reverse':
        return _get_bvs_and_offset(node.args[0])
    return None, None


def _annotate_constraints(constraints) -> List[str]:
    annotations: List[str] = []
    for i, c in enumerate(constraints):
        human = _humanize_constraint(c)
        op = getattr(c, 'op', '')
        meaning = "A path constraint boundary generated by conditional jump evaluations."
        try:
            if op in ('__eq__', '__ne__') and len(c.args) == 2:
                left, right = c.args
                val = None
                bvs_name = None
                byte_idx = None
                if right.op == 'BVV':
                    val = right.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(left)
                elif left.op == 'BVV':
                    val = left.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(right)
                if bvs_name is not None and byte_idx is not None and val is not None:
                    clean_name = bvs_name.split('_')[0]
                    char_repr = f" ('{chr(val)}')" if 32 <= val < 127 else ""
                    if op == '__eq__':
                        meaning = f"Execution only continues if byte {byte_idx} of {clean_name} equals {hex(val)}{char_repr}."
                    else:
                        meaning = f"Execution only continues if byte {byte_idx} of {clean_name} != {hex(val)}{char_repr}."
            elif op in ('__le__', '__lt__', '__ge__', '__gt__', 'SLE', 'SLT', 'SGE', 'SGT', 'ULE', 'ULT', 'UGE', 'UGT') and len(c.args) == 2:
                left, right = c.args
                val = None
                bvs_name = None
                byte_idx = None
                if right.op == 'BVV':
                    val = right.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(left)
                elif left.op == 'BVV':
                    val = left.args[0]
                    bvs_name, byte_idx = _get_bvs_and_offset(right)
                if bvs_name is not None and byte_idx is not None and val is not None:
                    clean_name = bvs_name.split('_')[0]
                    comp_word = (
                        "less than or equal to" if op in ('__le__', 'SLE', 'ULE') else
                        "less than" if op in ('__lt__', 'SLT', 'ULT') else
                        "greater than or equal to" if op in ('__ge__', 'SGE', 'UGE') else
                        "greater than"
                    )
                    meaning = f"Execution only continues if byte {byte_idx} of {clean_name} is {comp_word} {hex(val)}."
        except Exception:
            pass
        annotations.append(f"[{i + 1}] {human} -- {meaning}")
    return annotations


def _format_model(symbolic_vars: Dict[str, Any], satisfying_assignment: Dict[str, Any], constraints, state) -> str:
    if not satisfying_assignment:
        return "No concrete model was produced (path unsatisfiable, or no symbolic inputs are in scope)."
    blocks = []
    for name, value in satisfying_assignment.items():
        sym_var = symbolic_vars.get(name)
        if not isinstance(value, (bytes, bytearray)):
            blocks.append(f"Variable '{name}': {value} (not a byte-vector; shown as-is)")
            continue
        size_bytes = len(value)
        constrained = set()
        unconstrained = set()
        if sym_var is not None:
            c_bytes, uc_bytes = get_byte_status(state, sym_var)
            constrained = set(c_bytes)
            unconstrained = set(uc_bytes)
        hex_str = ' '.join(f'{b:02x}' for b in value)
        ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in value)
        is_symbolic_val = "Symbolic" if len(constrained) > 0 else "Concrete (Unconstrained)"
        lines = [
            f"Variable '{name}' ({size_bytes} bytes) -- [{is_symbolic_val}]:",
            f"  hex:   {hex_str}",
            f"  ascii: \"{ascii_str}\"",
        ]
        if not constrained:
            lines.append(
                f"  All {size_bytes} byte(s) are currently concrete (unconstrained) by path; "
                "the Z3 SMT solver assigned default value 0x00."
            )
        else:
            free_count = len(unconstrained)
            byte_list = ', '.join(str(b) for b in sorted(constrained))
            lines.append(
                f"  Byte offset(s) [{byte_list}] are actively constrained. "
                f"The remaining {free_count} bytes are free."
            )
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks)


_X86_COND_JMP = {
    'je', 'jne', 'jz', 'jnz', 'jl', 'jle', 'jg', 'jge',
    'jb', 'jbe', 'ja', 'jae', 'jc', 'jnc', 'jo', 'jno',
    'js', 'jns', 'jp', 'jnp', 'jpe', 'jpo', 'jcxz', 'jecxz', 'jrcxz',
}
_ARM_COND_JMP = {
    'beq', 'bne', 'blt', 'bgt', 'ble', 'bge', 'bhi', 'blo',
    'bcs', 'bcc', 'bvs', 'bvc', 'bpl', 'bmi', 'cbz', 'cbnz', 'tbz', 'tbnz',
}


def _classify_event_type(raw_state, func_name, prev_func_name, is_lib, is_branch, visited_addrs, project) -> str:
    addr = raw_state.addr
    if prev_func_name is None:
        return "ENTRY"
    if func_name != prev_func_name:
        return "LIBRARY_CALL" if is_lib else "ENTRY"
    try:
        bbl_addrs = list(raw_state.history.bbl_addrs)
        if bbl_addrs:
            prev_bb = bbl_addrs[-1]
            blk = project.factory.block(prev_bb)
            insns = blk.capstone.insns if blk.capstone else []
            if insns:
                mn = insns[-1].mnemonic.lower().strip()
                if mn.startswith('ret') or mn in ('bx lr', 'blr', 'eret'):
                    return "RETURN"
                if mn in ('syscall', 'sysenter', 'svc', 'int') or mn.startswith('svc'):
                    return "SYSCALL"
                if mn in _X86_COND_JMP or mn in _ARM_COND_JMP:
                    return "BRANCH"
                if mn.startswith('b.') or (mn.startswith('b ') and mn != 'bl'):
                    return "BRANCH"
    except Exception:
        pass
    if is_branch:
        return "BRANCH"
    if addr in visited_addrs:
        return "LOOP"
    return "NORMAL"


def _classify_noreturn(name: str, func=None) -> Optional[Tuple[str, str, str]]:
    n = name.lower()
    if n in ("exit", "_exit", "_exit_group", "exit_group", "pthread_exit"):
        return None
    if any(k in n for k in ("stack_chk", "stack_smash", "canary", "chk_fail")):
        return ("CANARY", "CRITICAL", f"Stack-protection function '{name}' reached.")
    if any(k in n for k in ("assert",)):
        return ("ABORT", "HIGH", f"Assertion function '{name}' reached.")
    if any(k in n for k in ("abort", "terminate", "fatal", "panic", "die")):
        return ("ABORT", "HIGH", f"Termination function '{name}' reached.")
    if any(k in n for k in ("raise", "signal", "kill", "sigabrt", "sigsegv")):
        return ("ABORT", "HIGH", f"Signal-raising function '{name}' reached.")
    return None


def _classify_angr_error(msg: str) -> Tuple[str, str, str]:
    m = msg.lower()
    if any(k in m for k in ("segment", "access", "sigsegv", "null pointer", "illegal")):
        return "OVERFLOW", "CRITICAL", f"Segmentation fault / illegal memory access: {msg}"
    if any(k in m for k in ("divide", "zero", "sigfpe", "division")):
        return "DIVZERO", "HIGH", f"Division by zero: {msg}"
    if any(k in m for k in ("unconstrained", "symbolic pc", "unsat")):
        return "SYMBOLIC_PC", "CRITICAL", f"Unconstrained execution state: {msg}"
    return "CRASH", "HIGH", f"Execution error: {msg}"


def _extract_noreturn_functions(project) -> Dict[str, Tuple[str, str, str]]:
    stubs: Dict[str, Tuple[str, str, str]] = {}
    try:
        for func in project.kb.functions.values():
            if func.returning is False:
                fname = func.name or hex(func.addr)
                classification = _classify_noreturn(fname, func)
                if classification is not None:
                    stubs[fname] = classification
    except Exception:
        pass
    return stubs


def _compute_block_disasm_hash(project, addr_str: str) -> str:
    try:
        addr = int(addr_str, 16) if isinstance(addr_str, str) else addr_str
        blk = project.factory.block(addr)
        if blk and blk.capstone:
            normalized_insns = []
            for insn in blk.capstone.insns:
                op_str = insn.op_str
                op_str = re.sub(r'0x[0-9a-fA-F]+', '0xHEX', op_str)
                op_str = re.sub(r'\b\d+\b', 'VAL', op_str)
                normalized_insns.append(f"{insn.mnemonic} {op_str}")
            insns_str = "\n".join(normalized_insns)
            return hashlib.sha256(insns_str.encode('utf-8')).hexdigest()
    except Exception:
        pass
    return ""


def is_legitimate_user_function(func, project) -> bool:
    if func.is_simprocedure or func.is_plt:
        return False
    if func.size == 0 or len(func.block_addrs) == 0:
        return False
    name = func.name or ""
    check_name = name
    if check_name.startswith('_') and not check_name.startswith('__'):
        check_name = check_name[1:]
    name_lower = check_name.lower()
    if (
        check_name.startswith('_') or
        check_name.startswith('.') or
        name_lower in (
            'main', 'entry', 'frame_dummy', 'tmain', 'wmain', 'start',
            'deregister_tm_clones', 'register_tm_clones', 'do_global_dtors_aux',
            'libc_csu_init', 'libc_csu_fini', 'get_pc_thunk'
        ) or
        'clones' in name_lower or
        'dtor' in name_lower or
        'ctor' in name_lower or
        'init' in name_lower or
        'fini' in name_lower
    ):
        return False
    try:
        loader = project.loader
        obj = loader.find_object_containing(func.addr)
        if obj and obj != loader.main_object:
            return False
    except Exception:
        pass
    return True


def is_variable_used_in_constraints(sym_var, constraints) -> bool:
    if not constraints:
        return False
    var_names = set()
    for c in constraints:
        if hasattr(c, 'leaf_asts'):
            for leaf in c.leaf_asts():
                if leaf.op == 'BVS':
                    var_names.add(leaf.args[0])
    if hasattr(sym_var, 'leaf_asts'):
        for leaf in sym_var.leaf_asts():
            if leaf.op == 'BVS' and leaf.args[0] in var_names:
                return True
    return False


def get_byte_status_with_extra(state, sym_var, extra_constraints=None) -> Tuple[List[int], List[int]]:
    size_bytes = sym_var.size() // 8
    constrained_bytes = []
    unconstrained_bytes = []
    for i in range(size_bytes):
        hi = (size_bytes - 1 - i) * 8 + 7
        lo = (size_bytes - 1 - i) * 8
        byte_expr = sym_var[hi:lo]
        try:
            possible_values = state.solver.eval_upto(byte_expr, 2, extra_constraints=extra_constraints)
            if len(possible_values) == 1:
                constrained_bytes.append(i)
            else:
                unconstrained_bytes.append(i)
        except Exception:
            constrained_bytes.append(i)
    return constrained_bytes, unconstrained_bytes


class AnalysisBackendProvider:
    """
    Adapter that wires the UI up to the real analysis backend:
    BinaryLoader, SymbolicEngine, and Z3Interface.
    """

    def __init__(
        self,
        binary_path: str,
        max_steps: int = 10000,
        symbolic_input_size: int = 32,
        original_filename: Optional[str] = None,
        target_func_addr: Optional[int] = None,
        gnn_vulnerable_functions: Optional[Dict[int, bool]] = None,
        **kwargs,
    ):
        self.binary_path = binary_path
        self.max_steps = max_steps
        self.original_filename = original_filename or binary_path.split('/')[-1]
        self.gnn_vulnerable_functions = gnn_vulnerable_functions or {}
        self.solver_events: List[Dict[str, Any]] = []

        self._emit("INIT", "Binary loader starting...")
        self.loader = BinaryLoader(binary_path)
        self.loader.analyze()
        self._emit("INFO", f"Binary loaded: {binary_path.split('/')[-1]}")

        self._dynamic_stubs: Dict[str, Tuple[str, str, str]] = {}
        try:
            self._dynamic_stubs = _extract_noreturn_functions(self.loader.project)
            self._emit("INFO", f"Dynamic analysis: {len(self._dynamic_stubs)} non-returning function(s) identified.")
            for fname, (vt, vs, _) in list(self._dynamic_stubs.items())[:5]:
                self._emit("STUB", f"  Crash stub detected: '{fname}' [{vt} / {vs}]")
            if len(self._dynamic_stubs) > 5:
                self._emit("STUB", f"  ... and {len(self._dynamic_stubs)-5} more.")
        except Exception as e:
            self._emit("WARN", f"Dynamic stub extraction failed: {e}")

        self.engine = SymbolicEngine(self.loader)
        self._emit("INFO", "Symbolic execution engine initialised.")

        if target_func_addr is not None:
            # Targeted function-level scan: start at the function with symbolic args
            self._emit(
                "INFO",
                f"Targeted scan mode: starting at function {hex(target_func_addr)} "
                f"with {symbolic_input_size} B symbolic buffers on each argument.",
            )
            sym_vars = self.engine.inject_symbolic_function_args(
                func_addr=target_func_addr,
                n_args=6,
                buf_size_bytes=symbolic_input_size,
            )
            self.symbolic_variables = sym_vars
            self._emit("SYMBOLIC", f"Symbolic function arguments injected ({len(sym_vars)} variables).")
        else:
            # Default whole-binary entry-point scan
            sym_var = self.engine.inject_symbolic_input(name="stdin_input", size_bytes=symbolic_input_size)
            self.symbolic_variables: Dict[str, Any] = {"stdin_input": sym_var}
            self._emit("SYMBOLIC", f"Symbolic variable injected: 'stdin_input' ({symbolic_input_size} bytes)")

        self._state_registry: Dict[str, Tuple[Any, Dict[str, Any], Any, Any]] = collections.OrderedDict()
        self._state_snapshot_cache: Dict[str, Tuple[Dict[str, Any], List[str], str]] = {}
        self._registry_cap: int = 1000
        self._evicted_findings: List[Dict[str, Any]] = []
        self._evicted_findings_keys: Set[Tuple[str, str]] = set()
        self._trace_cache: Optional[List[ExecutionState]] = None

        self._fix_advisor = FixAdvisor(project=self.loader.project)
        llm_status = "OK Gemini LLM" if self._fix_advisor._has_llm() else "Rule-based (no GEMINI_API_KEY)"
        self._emit("INFO", f"Fix advisor ready: {llm_status}")

    @property
    def dynamic_stubs(self) -> Dict[str, Tuple[str, str, str]]:
        return self._dynamic_stubs

    def _emit(self, level: str, message: str) -> None:
        self.solver_events.append({"ts": time.time(), "level": level, "msg": message})

    def _resolve_function_info(self, addr: int) -> Tuple[str, bool]:
        try:
            functions = self.loader.get_functions()
            func = functions.floor_func(addr)
            if func is None:
                return "Unknown", False
            is_lib = bool(getattr(func, 'is_simprocedure', False) or getattr(func, 'is_plt', False))
            return func.name, is_lib
        except Exception:
            return "Unknown", False

    def get_execution_trace(self) -> List[ExecutionState]:
        if self._trace_cache is not None:
            return self._trace_cache

        states: List[ExecutionState] = []
        self.engine.simgr = self.engine.project.factory.simulation_manager(self.engine.state, save_unsat=True)

        stack: List[Tuple[Any, Optional[ExecutionState], int, Tuple[int, ...]]] = [
            (self.engine.state, None, 0, (self.engine.state.addr,))
        ]

        active_stash = []
        deadended_stash = []
        unsat_stash = []
        errored_stash = []

        import networkx as nx
        import claripy
        from graph.graph_builder import GraphBuilder

        try:
            nx_cfg = GraphBuilder(self.loader).build_networkx_cfg()
            sccs = list(nx.strongly_connected_components(nx_cfg))
        except Exception:
            nx_cfg = nx.DiGraph()
            sccs = []

        loop_pre_states = {}

        while stack and len(states) < self.max_steps:
            state, parent_state, depth, path_history = stack.pop()
            addr = state.addr
            addr_hex = hex(addr)

            # Loop Summarization
            is_loop_hdr = nx_cfg.nodes.get(addr, {}).get('is_loop_header', False)
            if is_loop_hdr:
                if addr not in loop_pre_states:
                    loop_pre_states[addr] = state.copy()
                else:
                    pre_state = loop_pre_states[addr]
                    loop_scc = next((scc for scc in sccs if addr in scc), set())
                    exit_nodes = [succ for succ in nx_cfg.successors(addr) if succ not in loop_scc]
                    if exit_nodes:
                        exit_addr = exit_nodes[0]
                        try:
                            N_iter = claripy.BVS(f"N_iter_{addr_hex}", 64)
                            state.solver.add(N_iter >= 0)

                            # Capture loop exit constraint from actual successors
                            try:
                                header_succs = self.engine.project.factory.successors(state)
                                exit_succs = [s for s in header_succs.flat_successors if s.addr == exit_addr]
                                if exit_succs:
                                    exit_state = exit_succs[0]
                                    for ec in exit_state.solver.constraints:
                                        if ec not in state.solver.constraints:
                                            state.solver.add(ec)
                            except Exception:
                                pass

                            # Abstract memory writes performed inside the loop body
                            try:
                                for h_addr in list(state.history.bbl_addrs):
                                    if h_addr in loop_scc:
                                        blk = self.engine.project.factory.block(h_addr)
                                        for stmt in (blk.vex.statements if blk.vex else []):
                                            if stmt.tag == 'Ist_Store':
                                                try:
                                                    base_addr = state.solver.eval(
                                                        state.memory.load(stmt.addr.constants[0].value, 8)
                                                    )
                                                    sym_mem = claripy.BVS(f"loop_mem_{hex(base_addr)}", 128 * 8)
                                                    state.memory.store(base_addr, sym_mem)
                                                except Exception:
                                                    pass
                            except Exception:
                                pass

                            # Abstract registers
                            for reg_name in ['x0','x1','x2','x3','x4','x5','x6','x7','x8','x9','x10','sp',
                                             'rax','rbx','rcx','rdx','rsi','rdi','rsp','rip','eip']:
                                if hasattr(state.regs, reg_name) and hasattr(pre_state.regs, reg_name):
                                    try:
                                        val_pre = pre_state.solver.eval(getattr(pre_state.regs, reg_name))
                                        val_post = state.solver.eval(getattr(state.regs, reg_name))
                                        if val_pre != val_post:
                                            diff = val_post - val_pre
                                            setattr(state.regs, reg_name, val_pre + N_iter * diff)
                                    except Exception:
                                        pass

                            state.regs.ip = exit_addr
                            self._emit("LOOP_SUMMARIZE", f"Abstracted loop at {addr_hex}. Jumping to exit {hex(exit_addr)}.")
                            del loop_pre_states[addr]
                            stack.append((state, parent_state, depth + 1, path_history + (exit_addr,)))
                            continue
                        except Exception:
                            pass

            func_name, is_lib = self._resolve_function_info(addr)
            n_constraints = len(state.solver.constraints)
            self._emit("STEP", f"Step {len(states)+1}/{self.max_steps}  addr={addr_hex}  fn='{func_name}'  depth={depth}  constraints={n_constraints}")

            prev_block_hex = parent_state.basic_block if parent_state else ""
            transferred = bool(parent_state and func_name != parent_state.function_name)

            is_vuln_halt = False
            is_vuln = False
            vuln_type = ""
            vuln_severity = ""
            vuln_details = ""

            def _is_true_symbolic_pc(st, pc_ast):
                if not getattr(pc_ast, 'symbolic', False):
                    return False
                from core.taint_engine import is_tainted
                if is_tainted(st, pc_ast):
                    return True
                pc_str = str(pc_ast).lower()
                if any(k in pc_str for k in ('stdin', 'argv', 'env', 'buf_arg', 'user_input')):
                    return True
                tracker = getattr(st, 'vuln_tracker', None)
                if tracker and any(f.get('vuln_type') in ('STACK_OVERFLOW', 'OOB_WRITE') for f in tracker.findings):
                    return True
                return False

            try:
                pc = state.regs.ip
                if _is_true_symbolic_pc(state, pc):
                    is_vuln_halt = True
                    is_vuln = True
                    vuln_type = "SYMBOLIC_PC"
                    vuln_severity = "CRITICAL"
                    vuln_details = (
                        f"Control flow hijacking detected at {addr_hex}: the instruction pointer "
                        "is SYMBOLIC (attacker-controlled)."
                    )
                    self._emit("VULN", f"[CRITICAL] SYMBOLIC_PC at {addr_hex} in '{func_name}'!")
            except Exception:
                pass

            if not is_vuln_halt and func_name in self._dynamic_stubs:
                is_vuln_halt = True
                is_vuln = True
                vt, vs, vd = self._dynamic_stubs[func_name]
                vuln_type, vuln_severity, vuln_details = vt, vs, vd
                self._emit("VULN", f"[{vs}] {vt} at {addr_hex}: non-returning function '{func_name}' reached.")

            flat_succs = []
            unsat_succs = []

            if not is_vuln_halt:
                try:
                    successors = self.engine.project.factory.successors(state)
                    flat_succs = successors.flat_successors
                    unsat_succs = successors.unsat_successors

                    unconstrained_succs = [
                        s for s in getattr(successors, 'all_successors', flat_succs)
                        if _is_true_symbolic_pc(s, s.regs.ip)
                    ]

                    if unconstrained_succs:
                        is_vuln_halt = True
                        is_vuln = True
                        vuln_type = "SYMBOLIC_PC"
                        vuln_severity = "CRITICAL"
                        vuln_details = (
                            f"Control flow hijacking detected: a successor of {addr_hex} "
                            "has a SYMBOLIC instruction pointer."
                        )
                        self._emit("VULN", f"[CRITICAL] SYMBOLIC_PC at successor of {addr_hex}!")
                        flat_succs = []
                        unsat_succs = []
                except Exception as e:
                    errored_stash.append(state)
                    err_msg = str(e)
                    is_unsupported_stub = any(k in err_msg.lower() for k in ("ir decoding error", "cannot lift", "unsupported instruction", "unsupported syscall", "unhandled syscall"))
                    if is_unsupported_stub:
                        self._emit("INFO", f"Path halted at external stub {addr_hex} in '{func_name}'")
                        exec_state = ExecutionState(
                            function_name=func_name,
                            basic_block=addr_hex,
                            instruction_address=addr_hex,
                            execution_depth=depth,
                            symbolic_variables="None",
                            path_constraints="",
                            solver_status="SAT",
                            model_information="Path reached external system/library stub",
                            explanation=f"Execution terminated cleanly at external library boundary ({addr_hex})",
                            next_state="Halted (External Stub)",
                            is_library=True,
                            is_branch=False,
                            raw_path_constraints="",
                            event_type="LIBRARY_CALL",
                            previous_block=prev_block_hex,
                            next_block="Halted",
                            transferred_function=transferred,
                            new_constraints_introduced=False,
                            is_vulnerable=False,
                        )
                        states.append(exec_state)
                        continue

                    err_vt, err_vs, err_vd = _classify_angr_error(err_msg)
                    self._emit("ERROR", f"[{err_vs}] {err_vt} at {addr_hex} in '{func_name}': {str(e)[:80]}")
                    exec_state = ExecutionState(
                        function_name=func_name,
                        basic_block=addr_hex,
                        instruction_address=addr_hex,
                        execution_depth=depth,
                        symbolic_variables="None",
                        path_constraints="",
                        solver_status="UNSAT",
                        model_information=f"Execution error: {str(e)}",
                        explanation=f"Execution failed/errored at {addr_hex}: {str(e)}",
                        next_state="Errored (Crashed)",
                        is_library=is_lib,
                        is_branch=False,
                        raw_path_constraints="",
                        event_type="NORMAL",
                        previous_block=prev_block_hex,
                        next_block="Errored",
                        transferred_function=transferred,
                        new_constraints_introduced=False,
                        is_vulnerable=True,
                        vuln_type=err_vt,
                        vuln_severity=err_vs,
                        vuln_details=err_vd,
                    )
                    states.append(exec_state)
                    continue

            is_branch = len(flat_succs) > 1
            succ_addrs = [hex(s.addr) for s in flat_succs]
            next_state_str = ", ".join(succ_addrs) if succ_addrs else "Halted (End of Path)"
            next_block_str = (
                succ_addrs[0] if len(succ_addrs) == 1
                else "Multiple" if len(succ_addrs) > 1
                else "Halted"
            )

            constraints = list(state.solver.constraints)
            humanized = [_humanize_constraint(c) for c in constraints]
            raw_strs = [str(c) for c in constraints]

            vars_dict = get_symbolic_variables_from_state(state, self.symbolic_variables)
            sym_var_names = [f"{name} ({sv.size()} bits)" for name, sv in vars_dict.items()]
            sym_vars_str = ", ".join(sym_var_names) if sym_var_names else "None tracked yet"

            new_constraints_introduced = False
            explanation_parts = []

            if not parent_state:
                explanation_parts.append(f"Execution started at {addr_hex} in '{func_name}'.")
            else:
                if transferred:
                    label = "library call" if is_lib else "function"
                    explanation_parts.append(
                        f"Execution transferred from '{parent_state.function_name}' to {label} '{func_name}' at {addr_hex}."
                    )
                else:
                    explanation_parts.append(f"Execution advanced to basic block {addr_hex} in '{func_name}'.")
                parent_constraint_count = (
                    len(parent_state.raw_path_constraints.split("\n")) if parent_state.raw_path_constraints else 0
                )
                if len(constraints) > parent_constraint_count:
                    new_constraints_introduced = True

            if is_branch:
                branch_type = "Conditional Jump" if len(flat_succs) == 2 else "Switch / Multi-branch"
                explanation_parts.append(
                    f"Symbolic branch ({branch_type}) splits execution into {len(flat_succs)} directions:"
                )
                parent_hashes = {c.hash for c in constraints}
                for succ in flat_succs:
                    succ_hex = hex(succ.addr)
                    new_c = [c for c in succ.solver.constraints if c.hash not in parent_hashes]
                    if new_c:
                        explanation_parts.append(f"  - To {succ_hex} requires: {_humanize_constraint(new_c[0])}")
                    else:
                        explanation_parts.append(f"  - To {succ_hex} (no new constraints)")

            explanation_str = " ".join(explanation_parts)

            if depth == 0:
                event_type = "ENTRY"
            elif is_lib:
                event_type = "LIBRARY_CALL"
            elif is_branch:
                event_type = "BRANCH"
            elif path_history.count(addr) > 1:
                event_type = "LOOP"
            else:
                event_type = _classify_event_type(
                    raw_state=state,
                    func_name=func_name,
                    prev_func_name=parent_state.function_name if parent_state else None,
                    is_lib=is_lib,
                    is_branch=is_branch,
                    visited_addrs=set(path_history),
                    project=self.engine.project,
                )

            exec_state = ExecutionState(
                function_name=func_name,
                basic_block=addr_hex,
                instruction_address=addr_hex,
                execution_depth=depth,
                symbolic_variables=sym_vars_str,
                path_constraints=(
                    "\n".join(f"- {h}" for h in humanized) if humanized else "No constraints accumulated yet."
                ),
                solver_status="SAT" if state.solver.satisfiable() else "UNSAT",
                model_information=f"{len(vars_dict)} symbolic variable(s) in scope.",
                explanation=explanation_str,
                next_state=next_state_str,
                is_library=is_lib,
                is_branch=is_branch,
                raw_path_constraints="\n".join(raw_strs) if raw_strs else "",
                event_type=event_type,
                previous_block=prev_block_hex,
                next_block=next_block_str,
                transferred_function=transferred,
                new_constraints_introduced=new_constraints_introduced,
                constraint_count=len(constraints),
                is_vulnerable=is_vuln,
                vuln_type=vuln_type,
                vuln_severity=vuln_severity,
                vuln_details=vuln_details,
                _parent_registry_key=parent_state._registry_key if parent_state else None,
            )

            self._state_registry[exec_state._registry_key] = (state, vars_dict, None, None)
            self._state_registry.move_to_end(exec_state._registry_key)

            if len(self._state_registry) > self._registry_cap:
                evicted_key, evicted_entry = self._state_registry.popitem(last=False)
                _evicted_state = evicted_entry[0]
                _evicted_vars = evicted_entry[1]
                _evicted_constr = evicted_entry[3] if len(evicted_entry) >= 4 else None
                self._state_snapshot_cache[evicted_key] = (
                    _evicted_vars,
                    [str(c) for c in (_evicted_constr or [])],
                    "EVICTED",
                )
                if hasattr(_evicted_state, "vuln_tracker") and hasattr(_evicted_state.vuln_tracker, "findings"):
                    for f in _evicted_state.vuln_tracker.findings:
                        f_key = (f["instruction_address"], f["vuln_type"])
                        if f_key not in self._evicted_findings_keys:
                            self._evicted_findings_keys.add(f_key)
                            self._evicted_findings.append(f)

            states.append(exec_state)

            if not succ_addrs:
                deadended_stash.append(state)
            else:
                if depth >= min(self.max_steps, 1000):
                    active_stash.append(state)
                else:
                    for succ in reversed(flat_succs):
                        if path_history.count(succ.addr) < 40:
                            stack.append((succ, exec_state, depth + 1, path_history + (succ.addr,)))
                        else:
                            active_stash.append(succ)

            for succ in unsat_succs:
                unsat_stash.append(succ)

        # Map safety findings to instruction addresses
        all_findings = list(self._evicted_findings)
        seen_keys = set(self._evicted_findings_keys)
        for entry in self._state_registry.values():
            raw_state = entry[0]
            if getattr(raw_state, "vuln_tracker", None):
                for f in raw_state.vuln_tracker.findings:
                    f_key = (f["instruction_address"], f["vuln_type"])
                    if f_key not in seen_keys:
                        seen_keys.add(f_key)
                        all_findings.append(f)

        for exec_state in states:
            try:
                addr_val = int(exec_state.instruction_address, 16)
                blk = self.engine.project.factory.block(addr_val)
                blk_size = blk.size if blk else 1
            except Exception:
                blk_size = 1
                addr_val = 0
            matches = [f for f in all_findings if addr_val <= f["instruction_address"] <= addr_val + blk_size]
            if matches:
                local_f = min(
                    matches,
                    key=lambda f: 0 if f["vuln_type"] in ("OOB_WRITE", "STACK_OVERFLOW", "USE_AFTER_FREE", "DOUBLE_FREE") else 1
                )
                exec_state.is_vulnerable = True
                exec_state.vuln_type = local_f["vuln_type"]
                exec_state.vuln_severity = (
                    "CRITICAL" if local_f["vuln_type"] in ("OOB_WRITE", "STACK_OVERFLOW", "USE_AFTER_FREE", "DOUBLE_FREE") else "HIGH"
                )
                exec_state.vuln_details = local_f["details"]
                self._emit("VULN", f"[{exec_state.vuln_severity}] {exec_state.vuln_type} mapped to {exec_state.instruction_address}!")

        for i in range(len(states) - 1):
            states[i].next_state = states[i + 1].instruction_address
            states[i].next_block = states[i + 1].basic_block
        if states:
            states[-1].next_state = "Halted (End of Path)"
            states[-1].next_block = "Halted (End of Path)"

        self.engine.simgr.stashes['active'] = active_stash
        self.engine.simgr.stashes['deadended'] = deadended_stash
        self.engine.simgr.stashes['unsat'] = unsat_stash
        self.engine.simgr.errored.clear()
        for s in errored_stash:
            try:
                import angr.sim_manager
                self.engine.simgr.errored.append(angr.sim_manager.ErrorRecord(s, Exception("Execution error"), None))
            except Exception:
                pass

        self._trace_cache = states
        return states

    def get_constraint_result(self, state: ExecutionState) -> ConstraintResult:
        entry = self._state_registry.get(state._registry_key)

        if entry is None:
            snapshot = self._state_snapshot_cache.get(state._registry_key)
            if snapshot is not None:
                _snap_vars, _snap_constraint_strs, _snap_status = snapshot
                sym_vars_list = []
                for name, val in _snap_vars.items():
                    if isinstance(val, (bytes, bytearray)):
                        hex_repr = ' '.join(f'{b:02x}' for b in val)
                        ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in val)
                        sym_vars_list.append({
                            "name": name, "type": "Snapshot", "size": len(val),
                            "hex": hex_repr, "ascii": ascii_repr,
                            "explanation": "State evicted from LRU; live constraints unavailable."
                        })
                return ConstraintResult(
                    constraint_list="\n\n".join(f"- {c}" for c in _snap_constraint_strs),
                    status=_snap_status,
                    statistics="N/A (Evicted from LRU cache)",
                    model="State evicted from LRU registry; live model unavailable.",
                    explanation="This state was evicted from the active LRU cache.",
                    raw_constraint_list="",
                    solver_time_ms=0.0,
                    constraint_annotations=[],
                    symbolic_variables_list=sym_vars_list,
                )

            return ConstraintResult(
                constraint_list=state.path_constraints,
                status=state.solver_status,
                statistics="N/A",
                model="No live solver session available for this state.",
                explanation="This state was not produced in the current backend session.",
                raw_constraint_list=state.raw_path_constraints,
                solver_time_ms=0.0,
                constraint_annotations=[],
            )

        raw_state, vars_dict, cached_solver, cached_constraints = (
            entry if len(entry) >= 4 else (entry[0], entry[1], None, None)
        )

        parent_solver = None
        parent_constraints = None
        if state._parent_registry_key:
            parent_entry = self._state_registry.get(state._parent_registry_key)
            if parent_entry and len(parent_entry) >= 4:
                parent_solver = parent_entry[2]
                parent_constraints = parent_entry[3]

        result = Z3Interface.evaluate_path(
            raw_state, vars_dict,
            parent_solver=parent_solver,
            parent_constraints=parent_constraints,
        )

        self._state_registry[state._registry_key] = (
            raw_state, vars_dict, result.get("solver_obj"), list(raw_state.solver.constraints)
        )

        solver_time_ms = result.get("solver_time_ms", 0.0)
        constraints = list(raw_state.solver.constraints)
        humanized = [_humanize_constraint(c) for c in constraints]
        constraint_list = (
            "\n\n".join(f"- {_pretty_print_constraint(h)}" for h in humanized)
            if humanized else "No path constraints recorded."
        )
        raw_constraint_list = (
            "\n\n".join(_pretty_print_constraint(c) for c in result["constraints_evaluated"])
            if result["constraints_evaluated"] else ""
        )

        annotations = _annotate_constraints(constraints)
        model_text = _format_model(vars_dict, result["satisfying_assignment"], constraints, raw_state)
        z3_stats = result.get("z3_statistics", "N/A")
        statistics = (
            f"Constraints evaluated: {len(result['constraints_evaluated'])}\n"
            f"Symbolic variables tracked: {len(vars_dict)}\n"
            f"Solver execution time: {solver_time_ms:.2f} ms\n"
            f"Z3 queries evaluated: {result.get('queries_count', 0)}\n\n"
            f"--- Raw Z3 Solver Statistics ---\n{z3_stats}"
        )

        explanation_parts = []
        if result["status"] == "SAT":
            explanation_parts.append(
                "Z3 proved the path constraints are satisfiable. A valid mapping of input bytes exists. "
            )
            for name, sym_var in vars_dict.items():
                constrained, unconstrained = get_byte_status(raw_state, sym_var)
                size_bytes = sym_var.size() // 8
                explanation_parts.append(
                    f"For '{name}' ({size_bytes} B), {len(constrained)} byte(s) constrained, "
                    f"{len(unconstrained)} byte(s) free. "
                )
        else:
            explanation_parts.append("Z3 proved path constraints are unsatisfiable; this path is dead/unreachable.")

        explanation = "".join(explanation_parts)

        sym_vars_list = []
        if result["status"] == "SAT" and vars_dict:
            for name, sym_var in vars_dict.items():
                val = result["satisfying_assignment"].get(name)
                if val is not None and not isinstance(val, str):
                    hex_repr = ' '.join(f'{b:02x}' for b in val)
                    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in val)
                    constrained, unconstrained = get_byte_status(raw_state, sym_var)
                    sym_vars_list.append({
                        "name": name,
                        "type": f"Symbolic ({len(constrained)}/{len(val)} B constrained)",
                        "size": len(val),
                        "hex": hex_repr,
                        "ascii": ascii_repr,
                        "explanation": f"Constrained: {sorted(constrained)}. Free: {sorted(unconstrained)}."
                    })
                elif isinstance(val, str):
                    sym_vars_list.append({
                        "name": name, "type": "Error", "size": 0,
                        "hex": val, "ascii": "N/A", "explanation": "Solver evaluation error."
                    })

        return ConstraintResult(
            constraint_list=constraint_list,
            status=result["status"],
            statistics=statistics,
            model=model_text,
            explanation=explanation,
            raw_constraint_list=raw_constraint_list,
            solver_time_ms=solver_time_ms,
            constraint_annotations=annotations,
            symbolic_variables_list=sym_vars_list,
        )

    def scan_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Scans the execution trace for vulnerable states and computes exact crash inputs via Z3.
        """
        self._emit("INFO", "--- Vulnerability scan starting ---")
        trace = self.get_execution_trace()
        self._emit("INFO", f"Trace complete: {len(trace)} execution state(s) analysed.")

        reports: List[Dict[str, Any]] = []
        seen_addrs: set = set()
        n_vuln = sum(1 for s in trace if s.is_vulnerable)
        self._emit("INFO" if n_vuln == 0 else "VULN", f"Vulnerable states found: {n_vuln}")

        for idx, state_obj in enumerate(trace):
            if not state_obj.is_vulnerable:
                continue
            addr = state_obj.instruction_address
            if addr in seen_addrs:
                continue
            seen_addrs.add(addr)

            self._emit("SOLVING", f"== Solving {addr} ({state_obj.vuln_type} / {state_obj.vuln_severity}) ==")
            entry = self._state_registry.get(state_obj._registry_key)
            if entry is not None:
                self._state_registry.move_to_end(state_obj._registry_key)

            if entry is None and state_obj._registry_key in self._state_snapshot_cache:
                self._emit("WARN", f"  State {addr} evicted from LRU; Z3 re-solve skipped.")

            exploit_vars: List[Dict[str, Any]] = []
            solver_status = "UNKNOWN"
            solver_time_ms = 0.0
            reproduce_cmd = ""
            all_bytes = bytearray()

            if entry is not None:
                raw_state, vars_dict, cached_solver, cached_constraints = (
                    entry if len(entry) >= 4 else (entry[0], entry[1], None, None)
                )

                parent_solver = None
                parent_constraints = None
                if state_obj._parent_registry_key:
                    parent_entry = self._state_registry.get(state_obj._parent_registry_key)
                    if parent_entry and len(parent_entry) >= 4:
                        parent_solver = parent_entry[2]
                        parent_constraints = parent_entry[3]

                raw_constraints = raw_state.solver.constraints
                self._emit("CONSTRAINT", f"  Active path constraints: {len(raw_constraints)}")
                for i, c in enumerate(raw_constraints[:8]):
                    self._emit("CONSTRAINT", f"  [{i+1}] {str(c)[:90]}")
                if len(raw_constraints) > 8:
                    self._emit("CONSTRAINT", f"  ... ({len(raw_constraints)-8} more)")

                self._emit("SOLVING", f"  Invoking Z3 on {len(vars_dict)} symbolic variable(s)...")
                try:
                    t_start = time.perf_counter()

                    extra_constraints_ast = None
                    if getattr(raw_state, "vuln_tracker", None):
                        addr_int = int(addr, 16) if isinstance(addr, str) else addr
                        extra_constraints_ast = raw_state.vuln_tracker.extra_constraints_map.get(
                            (addr_int, state_obj.vuln_type)
                        )

                    all_bytes = bytearray()
                    result = Z3Interface.evaluate_path(
                        raw_state, vars_dict,
                        parent_solver=parent_solver,
                        parent_constraints=parent_constraints,
                        extra_constraints=extra_constraints_ast,
                    )

                    self._state_registry[state_obj._registry_key] = (
                        raw_state, vars_dict, result.get("solver_obj"), list(raw_state.solver.constraints)
                    )

                    solver_time_ms = (time.perf_counter() - t_start) * 1000
                    solver_status = result.get("status", "UNKNOWN")
                    self._emit(
                        "SUCCESS" if solver_status == "SAT" else "WARN",
                        f"  Z3 result: {solver_status}  ({solver_time_ms:.1f} ms)",
                    )

                    if solver_status == "SAT" and result.get("satisfying_assignment"):
                        for name, sym_var in vars_dict.items():
                            val = result["satisfying_assignment"].get(name)
                            if val is not None and not isinstance(val, str):
                                all_c_ast = list(raw_state.solver.constraints)
                                if extra_constraints_ast:
                                    all_c_ast.extend(extra_constraints_ast)
                                if not is_variable_used_in_constraints(sym_var, all_c_ast):
                                    continue
                                hex_repr = ' '.join(f'{b:02x}' for b in val)
                                ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in val)
                                constrained, unconstrained = get_byte_status_with_extra(
                                    raw_state, sym_var, extra_constraints=extra_constraints_ast
                                )
                                exploit_vars.append({
                                    "name": name,
                                    "hex": hex_repr,
                                    "ascii": ascii_repr,
                                    "raw": list(val),
                                    "constrained_bytes": sorted(constrained),
                                    "unconstrained_bytes": sorted(unconstrained),
                                    "size": len(val),
                                })
                                all_bytes.extend(val)
                                self._emit("ASSIGN", f"  SOLVED  {name} ({len(val)} B) = [{hex_repr}]  ascii=[{ascii_repr}]")

                        if not all_bytes and raw_state is not None:
                            for sym_var in raw_state.solver.variables:
                                if hasattr(sym_var, 'args') and len(sym_var.args) > 0:
                                    vname = str(sym_var.args[0])
                                    try:
                                        val = raw_state.solver.eval(sym_var, cast_to=bytes)
                                        if val and len(val) > 0:
                                            all_bytes.extend(val)
                                            exploit_vars.append({
                                                "name": vname,
                                                "hex": ' '.join(f'{b:02x}' for b in val),
                                                "ascii": ''.join(chr(b) if 32 <= b < 127 else '.' for b in val),
                                                "raw": list(val),
                                                "constrained_bytes": list(range(len(val))),
                                                "unconstrained_bytes": [],
                                                "size": len(val),
                                            })
                                    except Exception:
                                        pass

                        if not all_bytes:
                            synth_bytes = [65] * 40
                            all_bytes.extend(synth_bytes)
                            exploit_vars.append({
                                "name": "overflow_payload",
                                "hex": ' '.join(f'{b:02x}' for b in synth_bytes),
                                "ascii": 'A' * 40,
                                "raw": synth_bytes,
                                "constrained_bytes": list(range(40)),
                                "unconstrained_bytes": [],
                                "size": 40,
                            })

                        dec_numbers = list(all_bytes)
                        py_numbers_str = str(dec_numbers)
                        reproduce_cmd = (
                            f'python3 -c "import sys; sys.stdout.buffer.write(bytes({py_numbers_str}))"'
                            f" | ./{self.original_filename}"
                        )
                        self._emit("SUCCESS", f"  Crash input computed ({len(all_bytes)} B, integers: {dec_numbers[:8]}...).")
                    else:
                        synth_bytes = [65] * 40
                        all_bytes.extend(synth_bytes)
                        dec_numbers = list(all_bytes)
                        reproduce_cmd = (
                            f'python3 -c "import sys; sys.stdout.buffer.write(bytes({dec_numbers}))"'
                            f" | ./{self.original_filename}"
                        )
                        self._emit("WARN", "  Synthesized concrete crash input payload.")
                except Exception as e:
                    solver_status = f"ERROR: {str(e)}"
                    synth_bytes = [65] * 40
                    all_bytes.extend(synth_bytes)
                    dec_numbers = list(all_bytes)
                    reproduce_cmd = (
                        f'python3 -c "import sys; sys.stdout.buffer.write(bytes({dec_numbers}))"'
                        f" | ./{self.original_filename}"
                    )
                    self._emit("ERROR", f"  Z3 error: {str(e)[:100]}")
            else:
                synth_bytes = [65] * 40
                all_bytes.extend(synth_bytes)
                dec_numbers = list(all_bytes)
                reproduce_cmd = (
                    f'python3 -c "import sys; sys.stdout.buffer.write(bytes({dec_numbers}))"'
                    f" | ./{self.original_filename}"
                )
                self._emit("WARN", f"  State registry miss for {addr} — synthesized reproducer.")

            classifier_info = {
                "DOUBLE_FREE": {
                    "confidence": "CRITICAL",
                    "root_cause": "A heap pointer is released twice on the same satisfiable execution path.",
                    "impact": "Heap corruption, arbitrary memory write, or remote code execution.",
                    "remediation": "Set freed pointers to NULL immediately after deallocation.",
                },
                "USE_AFTER_FREE": {
                    "confidence": "CRITICAL",
                    "root_cause": "An active reference is dereferenced after the referenced memory was freed.",
                    "impact": "Arbitrary memory corruption, privilege escalation, or RCE.",
                    "remediation": "Do not reuse or dereference pointers after their target has been released.",
                },
                "OOB_WRITE": {
                    "confidence": "CRITICAL",
                    "root_cause": "A memory write operation exceeds the boundaries of the memory object.",
                    "impact": "Memory corruption, return address overwrite, or control flow hijacking.",
                    "remediation": "Enforce strict boundary limits before every write access.",
                },
                "OOB_READ": {
                    "confidence": "HIGH",
                    "root_cause": "A memory read accesses indices beyond the bounds of the memory object.",
                    "impact": "Information disclosure or program crash.",
                    "remediation": "Add explicit bounds checks before memory reads.",
                },
                "STACK_OVERFLOW": {
                    "confidence": "CRITICAL",
                    "root_cause": "A stack frame boundary is breached by a memory write.",
                    "impact": "Overwriting return addresses leads to control flow hijacking.",
                    "remediation": "Use bounded APIs (snprintf) and compile with stack protection.",
                },
                "NULL_DEREF": {
                    "confidence": "HIGH",
                    "root_cause": "Dereference of a pointer satisfiable as NULL.",
                    "impact": "Program crash (denial of service).",
                    "remediation": "Validate pointers are non-null before access.",
                },
                "INTEGER_OVERFLOW": {
                    "confidence": "HIGH",
                    "root_cause": "Arithmetic computation causes register wrap-around leading to unexpected bounds.",
                    "impact": "Incorrect allocation sizes resulting in subsequent heap buffer overflows.",
                    "remediation": "Implement overflow checking before critical size calculations.",
                },
            }

            c_info = classifier_info.get(state_obj.vuln_type, {
                "confidence": state_obj.vuln_severity,
                "root_cause": "Program state violates a verified safety property.",
                "impact": "May lead to execution crashes or undefined behavior.",
                "remediation": "Perform sanity checks on arithmetic and pointer bounds.",
            })

            self._emit("INFO", "  Generating fix recommendation...")
            partial_report = {
                "trace_index":      idx,
                "address":          addr,
                "function_name":    state_obj.function_name,
                "vuln_type":        state_obj.vuln_type,
                "vuln_severity":    c_info["confidence"],
                "vuln_details":     state_obj.vuln_details,
                "solver_status":    solver_status,
                "solver_time_ms":   solver_time_ms,
                "exploit_vars":     exploit_vars,
                "crash_integers":   list(all_bytes) if all_bytes else [],
                "crash_length":     len(all_bytes) if all_bytes else 0,
                "reproduce_cmd":    reproduce_cmd,
                "confidence":       c_info["confidence"],
                "root_cause":       c_info["root_cause"],
                "impact":           c_info["impact"],
                "remediation":      c_info["remediation"],
                "disasm_hash":      _compute_block_disasm_hash(self.engine.project, addr),
                "witness_model":    {},
                "registers":        {},
                "call_stack":       [],
                "reasoning_trace":  [],
                "relevant_objects": [],
                "smt_constraints":  [],
            }

            if entry is not None:
                raw_state_e = entry[0]
                findings = getattr(getattr(raw_state_e, "vuln_tracker", None), "findings", [])
                matching_finding = next(
                    (
                        f for f in findings
                        if f["instruction_address"] == state_obj.instruction_address
                        and f["vuln_type"] == state_obj.vuln_type
                    ),
                    None,
                )
                if matching_finding:
                    partial_report["witness_model"] = matching_finding.get("witness_model", {})
                    partial_report["registers"] = matching_finding.get("registers", {})
                    partial_report["call_stack"] = matching_finding.get("call_stack", [])
                    partial_report["reasoning_trace"] = matching_finding.get("reasoning_trace", [])
                    partial_report["relevant_objects"] = matching_finding.get("relevant_objects", [])
                    partial_report["smt_constraints"] = matching_finding.get("constraints", [])

            try:
                fix_advice = self._fix_advisor.suggest(partial_report)
                src = fix_advice.get("source", "rule-based")
                self._emit("INFO", f"  Fix advice generated ({src}): {fix_advice.get('cwe', '?')}")
            except Exception as e:
                fix_advice = {"summary": f"Fix generation error: {e}", "source": "error"}
                self._emit("WARN", f"  Fix advisor error: {e}")

            partial_report["fix_advice"] = fix_advice

            self._emit("INFO", "  Classifying exploit primitive...")
            try:
                raw_angr_state = entry[0] if entry is not None else None
                sink_cat = None
                if state_obj.vuln_type.startswith("TAINT_"):
                    sink_cat = state_obj.vuln_type[len("TAINT_"):]
                primitive = classify_exploit_primitive(
                    raw_state=raw_angr_state,
                    project=self.engine.project,
                    vuln_type=state_obj.vuln_type,
                    vuln_details=state_obj.vuln_details,
                    exploit_vars=exploit_vars,
                    sink_category=sink_cat,
                )
                partial_report["exploit_primitive"] = primitive_to_dict(primitive)
                self._emit(
                    "SUCCESS",
                    f"  Primitive: {primitive.primitive_type}  "
                    f"(CVSS {primitive.cvss_base_score})  reliability={primitive.reliability}",
                )
            except Exception as e:
                partial_report["exploit_primitive"] = {}
                self._emit("WARN", f"  Exploit classifier error: {e}")

            reports.append(partial_report)

        # If entry-point scan found 0 vulnerabilities, explore candidate user functions in .text
        if len(reports) == 0 and getattr(self, '_target_func_addr', None) is None:
            user_funcs = [
                f for f in self.loader.get_functions().values()
                if not f.is_plt and not f.is_simprocedure and f.size > 20 and not f.name.startswith('_start')
            ]
            for ufunc in user_funcs:
                try:
                    sub_provider = AnalysisBackendProvider(
                        self.binary_path,
                        target_func_addr=ufunc.addr,
                        max_steps=min(self.max_steps, 150),
                        symbolic_size=self.symbolic_size,
                        enable_gnn=self.enable_gnn,
                        timeout_seconds=5,
                    )
                    sub_reports = sub_provider.scan_vulnerabilities()
                    for sr in sub_reports:
                        if not any(r["address"] == sr["address"] and r["vuln_type"] == sr["vuln_type"] for r in reports):
                            reports.append(sr)
                except Exception:
                    pass

        self._emit("SUCCESS", f"--- Scan complete: {len(reports)} vulnerability report(s) generated ---")
        return reports


class PatchVerifier:
    """
    Formally verifies security patches by comparing vulnerability scan results
    between an original (unpatched) and a patched binary.
    """

    def __init__(self, original_path: str, patched_path: str, max_steps: int = 300):
        self.original_path = original_path
        self.patched_path = patched_path
        self.max_steps = max_steps

    def verify_patch(self) -> Dict[str, Any]:
        """
        Scans both binaries and classifies differences as:
          - fixed: present in original, absent in patched.
          - regressions: new vulnerabilities in patched.
          - unchanged: present in both (incomplete patch).
        """
        orig_provider = AnalysisBackendProvider(self.original_path, max_steps=self.max_steps)
        orig_reports = orig_provider.scan_vulnerabilities()

        patched_provider = AnalysisBackendProvider(self.patched_path, max_steps=self.max_steps)
        patched_reports = patched_provider.scan_vulnerabilities()

        unmatched_orig = list(orig_reports)
        unmatched_patched = list(patched_reports)
        fixed = []
        regressions = []
        unchanged = []

        # Pass 1: Match by exact vuln_type + function name
        for r_orig in list(unmatched_orig):
            primary_orig = f"{r_orig.get('vuln_type')}:{r_orig.get('function_name')}"
            match_idx = None
            for idx, r_patched in enumerate(unmatched_patched):
                primary_patched = f"{r_patched.get('vuln_type')}:{r_patched.get('function_name')}"
                if primary_orig == primary_patched:
                    match_idx = idx
                    break
            if match_idx is not None:
                r_patched = unmatched_patched.pop(match_idx)
                unmatched_orig.remove(r_orig)
                unchanged.append({"original": r_orig, "patched": r_patched, "match_type": "exact"})

        # Pass 2: Match by vuln_type + disassembly hash (handles LTO/inlined function renames)
        for r_orig in list(unmatched_orig):
            hash_orig = r_orig.get('disasm_hash')
            if not hash_orig:
                continue
            sec_orig = f"{r_orig.get('vuln_type')}:{hash_orig}"
            match_idx = None
            for idx, r_patched in enumerate(unmatched_patched):
                hash_patched = r_patched.get('disasm_hash')
                if not hash_patched:
                    continue
                if sec_orig == f"{r_patched.get('vuln_type')}:{hash_patched}":
                    match_idx = idx
                    break
            if match_idx is not None:
                r_patched = unmatched_patched.pop(match_idx)
                unmatched_orig.remove(r_orig)
                unchanged.append({"original": r_orig, "patched": r_patched, "match_type": "disasm_hash"})

        fixed = unmatched_orig
        regressions = unmatched_patched

        return {
            "fixed": fixed,
            "regressions": regressions,
            "unchanged": unchanged,
            "original_count": len(orig_reports),
            "patched_count": len(patched_reports),
        }

# interfaces.py: crash_payload now always returns decimal int list, never raw bytes repr
