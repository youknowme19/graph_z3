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
    return ("CRASH", "HIGH", f"Non-returning function '{name}' reached (angr confirmed it never returns).")


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

            try:
                pc = state.regs.ip
                if pc.symbolic:
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
