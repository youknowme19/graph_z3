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


_SIGNAL_NAMES: Dict[int, str] = {
    4: "SIGILL",
    5: "SIGTRAP",
    6: "SIGABRT",
    7: "SIGEMT",
    8: "SIGFPE",
    9: "SIGKILL",
    10: "SIGBUS",
    11: "SIGSEGV",
    12: "SIGSYS",
}


def verify_live_crash(
    binary_path: str,
    payload: bytes,
    vuln_type: str = "",
    timeout_s: float = 2.0,
    is_targeted_func: bool = False,
) -> Dict[str, Any]:
    """
    Independently replay a synthesized witness payload against the native target binary
    via subprocess execution and verify whether it triggers an authentic crash signal.

    A witness is considered verified ONLY when the native binary terminates with a crash
    signal (e.g. SIGSEGV, SIGABRT, SIGTRAP, SIGBUS, SIGILL, SIGFPE) or sanitizer fault.
    Timeouts, missing payloads, or normal exits are never counted as verified crashes.
    """
    import os
    import subprocess

    if not payload:
        return {
            "attempted": False,
            "crashed": False,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "method": "none",
            "reason": "Empty witness payload",
        }

    if not binary_path or not os.path.isfile(binary_path):
        return {
            "attempted": False,
            "crashed": False,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "method": "none",
            "reason": "Binary file not found",
        }

    if binary_path.endswith(".o") or not os.access(binary_path, os.X_OK):
        return {
            "attempted": False,
            "crashed": False,
            "returncode": None,
            "signal": None,
            "timed_out": False,
            "method": "none",
            "reason": "Target is a non-executable object file",
        }

    def _run_once(env_override: Optional[Dict[str, str]] = None, method_label: str = "native") -> Dict[str, Any]:
        try:
            proc = subprocess.run(
                [binary_path],
                input=bytes(payload),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_s,
                env=env_override,
            )
            rc = proc.returncode
            stderr_text = proc.stderr.decode("utf-8", errors="replace") if proc.stderr else ""
            sig_num = None
            if rc < 0:
                sig_num = -rc
            elif rc > 128 and (rc - 128) in _SIGNAL_NAMES:
                sig_num = rc - 128

            sanitizer_fault = any(
                tok in stderr_text
                for tok in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "GuardMalloc", "malloc: *** error")
            )
            crashed = (sig_num in _SIGNAL_NAMES) or (rc != 0 and sanitizer_fault)
            sig_name = _SIGNAL_NAMES.get(sig_num, f"SIG({sig_num})") if sig_num else (
                "SANITIZER_ABORT" if crashed else None
            )
            return {
                "attempted": True,
                "crashed": bool(crashed),
                "returncode": rc,
                "signal": sig_name,
                "timed_out": False,
                "method": method_label,
                "reason": (
                    f"Process terminated with {sig_name} (rc={rc})"
                    if crashed
                    else f"Process exited without crash (rc={rc})"
                ),
            }
        except subprocess.TimeoutExpired:
            return {
                "attempted": True,
                "crashed": False,
                "returncode": None,
                "signal": None,
                "timed_out": True,
                "method": method_label,
                "reason": f"Execution timed out after {timeout_s}s",
            }
        except OSError as exc:
            return {
                "attempted": False,
                "crashed": False,
                "returncode": None,
                "signal": None,
                "timed_out": False,
                "method": method_label,
                "reason": f"OS execution error: {exc}",
            }

    res = _run_once(env_override=None, method_label="native")
    if res["crashed"] or res["timed_out"] or not res["attempted"]:
        return res

    # On macOS, standard system malloc does not immediately unmap small freed heap chunks;
    # re-verify heap safety violations under built-in GuardMalloc (/usr/lib/libgmalloc.dylib).
    gmalloc_path = "/usr/lib/libgmalloc.dylib"
    if vuln_type in ("USE_AFTER_FREE", "DOUBLE_FREE", "INVALID_FREE", "OOB_WRITE", "OOB_READ") and os.path.exists(gmalloc_path):
        env_gm = dict(os.environ)
        env_gm["DYLD_INSERT_LIBRARIES"] = gmalloc_path
        gm_res = _run_once(env_override=env_gm, method_label="native+libgmalloc")
        if gm_res["crashed"]:
            return gm_res

    if is_targeted_func and not res["crashed"]:
        res["reason"] = f"{res['reason']} (targeted function entry may not be reachable via default main/stdin harness)"
    return res


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


_INTERNAL_SYM_PREFIXES = (
    "strlen_", "reg_", "mem_", "unconstrained_", "N_iter_", "loop_mem_", "sim_data_", "fs_"
)


def _is_attacker_controlled_var_name(name: str) -> bool:
    if not name:
        return False
    low = str(name).lower()
    if any(low.startswith(p.lower()) for p in _INTERNAL_SYM_PREFIXES):
        return False
    return any(k in low for k in ("stdin", "taint_", "argv", "env", "buf_arg", "arg_", "user_input", "input"))


def _taint_var_sort_key(name: str) -> Tuple[int, int, str]:
    m = re.search(r"taint_[a-zA-Z0-9_]+_(0x[0-9a-fA-F]+)_byte(\d+)", str(name))
    if m:
        try:
            return (0, int(m.group(2)), str(name))
        except Exception:
            pass
    if str(name).startswith("stdin"):
        return (1, 0, str(name))
    return (2, 0, str(name))


def _iter_leaf_asts(ast_obj):
    """Safely iterate leaf ASTs of a claripy AST regardless of whether leaf_asts is a method or iterable."""
    if ast_obj is None or not hasattr(ast_obj, "leaf_asts"):
        return ()
    la = getattr(ast_obj, "leaf_asts")
    try:
        return la() if callable(la) else la
    except Exception:
        return ()


def get_symbolic_variables_from_state(state, injected_vars, extra_constraints=None) -> Dict[str, Any]:
    vars_dict = dict(injected_vars or {})
    seen_bvs_names = {
        str(v.args[0]) for v in vars_dict.values()
        if getattr(v, "op", None) == "BVS" and getattr(v, "args", None)
    }

    tracker = getattr(state, "vuln_tracker", None) if state is not None else None
    if tracker is not None and hasattr(tracker, "symbolic_variables"):
        for k, v in tracker.symbolic_variables.items():
            if k not in vars_dict and getattr(v, "op", None) == "BVS" and _is_attacker_controlled_var_name(k):
                bvs_internal = str(v.args[0]) if getattr(v, "args", None) else str(k)
                if bvs_internal not in seen_bvs_names:
                    vars_dict[k] = v
                    seen_bvs_names.add(bvs_internal)

    def walk(node):
        for leaf in _iter_leaf_asts(node):
            if getattr(leaf, 'op', None) == 'BVS' and getattr(leaf, 'args', None):
                name = str(leaf.args[0])
                if name not in vars_dict and name not in seen_bvs_names and _is_attacker_controlled_var_name(name):
                    vars_dict[name] = leaf
                    seen_bvs_names.add(name)

    if state is not None and hasattr(state, "solver"):
        for constraint in state.solver.constraints:
            walk(constraint)
    if extra_constraints:
        for constraint in extra_constraints:
            walk(constraint)
    return dict(sorted(vars_dict.items(), key=lambda kv: _taint_var_sort_key(kv[0])))


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
    # Tool/framework exceptions (e.g. claripy type errors, unsupported instructions)
    # should be classified as engine simulation errors, not false positive security vulnerabilities.
    if any(k in m for k in ("claripy", "must have the same length", "not implemented", "unsupported", "keyerror", "attributeerror")):
        return "SIMULATION_ERROR", "INFO", f"Analysis engine simulation error: {msg}"
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
    if not constraints or sym_var is None:
        return False
    var_names = set()
    for c in constraints:
        for leaf in _iter_leaf_asts(c):
            if getattr(leaf, 'op', None) == 'BVS' and getattr(leaf, 'args', None):
                var_names.add(str(leaf.args[0]))
    for leaf in _iter_leaf_asts(sym_var):
        if getattr(leaf, 'op', None) == 'BVS' and getattr(leaf, 'args', None):
            if str(leaf.args[0]) in var_names:
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
        gnn_vulnerable_functions: Optional[Dict[int, Any]] = None,
        gnn_node_scores: Optional[Dict[int, float]] = None,
        scheduler_mode: Optional[str] = None,
        depth_penalty_lambda: float = 0.02,
        timeout_seconds: Optional[float] = None,
        **kwargs,
    ):
        self.binary_path = binary_path
        self.max_steps = max_steps
        self.symbolic_size = symbolic_input_size
        self._target_func_addr = target_func_addr
        self.original_filename = original_filename or binary_path.split('/')[-1]
        self.gnn_vulnerable_functions = gnn_vulnerable_functions or {}
        self.gnn_node_scores: Dict[int, float] = {
            int(k): float(v) for k, v in (gnn_node_scores or {}).items()
        }
        self.enable_gnn = bool(self.gnn_vulnerable_functions or self.gnn_node_scores)
        if scheduler_mode is not None:
            mode_norm = str(scheduler_mode).strip().lower()
            if mode_norm not in ("dfs", "maxheap"):
                raise ValueError(f"Unsupported scheduler_mode '{scheduler_mode}'; expected 'dfs' or 'maxheap'.")
            self.scheduler_mode = mode_norm
        else:
            self.scheduler_mode = "maxheap" if self.enable_gnn else "dfs"
        self.depth_penalty_lambda = float(depth_penalty_lambda)
        self.timeout_seconds = float(timeout_seconds) if timeout_seconds is not None else None
        self.scheduler_telemetry: Dict[str, Any] = {
            "scheduler_mode": self.scheduler_mode,
            "max_steps_budget": self.max_steps,
            "timeout_seconds_budget": self.timeout_seconds,
            "depth_penalty_lambda": self.depth_penalty_lambda,
            "states_explored": 0,
            "max_frontier_size": 0,
            "elapsed_trace_ms": 0.0,
            "timed_out": False,
            "steps_to_first_vuln": None,
            "time_to_first_vuln_ms": None,
            "vulnerable_states_found": 0,
            "solver_status_counts": {"SAT": 0, "UNSAT": 0, "UNKNOWN": 0, "TIMEOUT": 0, "ERROR": 0},
            "verified_exploits_count": 0,
        }
        self.solver_events: List[Dict[str, Any]] = []

        self._emit("INIT", "Binary loader starting...")
        shared_loader = kwargs.get("_shared_loader")
        if shared_loader is not None:
            self.loader = shared_loader
        else:
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

    def _get_base_node_risk(self, addr: int) -> float:
        if addr in self.gnn_node_scores:
            return float(self.gnn_node_scores[addr])
        if addr in self.gnn_vulnerable_functions:
            val = self.gnn_vulnerable_functions[addr]
            if isinstance(val, (int, float)) and not isinstance(val, bool):
                return float(val)
            return 1.0 if val else 0.0
        try:
            functions = self.loader.get_functions()
            fn = functions.floor_func(addr) if functions else None
            if fn is not None:
                if fn.addr in self.gnn_node_scores:
                    return float(self.gnn_node_scores[fn.addr])
                if fn.addr in self.gnn_vulnerable_functions:
                    val = self.gnn_vulnerable_functions[fn.addr]
                    if isinstance(val, (int, float)) and not isinstance(val, bool):
                        return float(val)
                    return 1.0 if val else 0.0
                for b_addr in getattr(fn, "block_addrs", ()):
                    if b_addr in self.gnn_node_scores and b_addr <= addr < b_addr + 256:
                        return float(self.gnn_node_scores[b_addr])
        except Exception:
            pass
        return 0.0

    def _compute_reachable_risk_map(self, nx_cfg) -> Dict[int, float]:
        """
        Precompute context-valid reachable GNN risk:
            R(u) = max_{v in Reachable(u)} P_GNN(v)
        excluding return edges (Ijk_Ret) so unrealizable caller-return paths do not pollute reachability.
        """
        import networkx as nx
        fwd_graph = nx.DiGraph()
        angr_cfg = self.loader.get_cfg()
        if angr_cfg is not None and getattr(angr_cfg, "graph", None) is not None:
            for node in angr_cfg.graph.nodes():
                if getattr(node, "addr", None) is not None:
                    fwd_graph.add_node(int(node.addr))
            for src, dst, data in angr_cfg.graph.edges(data=True):
                jk = (data or {}).get("jumpkind", "")
                if jk == "Ijk_Ret":
                    continue
                if getattr(src, "addr", None) is not None and getattr(dst, "addr", None) is not None:
                    fwd_graph.add_edge(int(src.addr), int(dst.addr))
        else:
            fwd_graph = nx_cfg.copy() if nx_cfg is not None else nx.DiGraph()

        base_risk: Dict[int, float] = {}
        functions = self.loader.get_functions()
        for u in fwd_graph.nodes():
            if u in self.gnn_node_scores:
                base_risk[u] = float(self.gnn_node_scores[u])
                continue
            if u in self.gnn_vulnerable_functions:
                val = self.gnn_vulnerable_functions[u]
                base_risk[u] = float(val) if isinstance(val, (int, float)) and not isinstance(val, bool) else (1.0 if val else 0.0)
                continue
            # If only function-level score is provided, do not assign the function's risk to a bare exit/return block
            if fwd_graph.out_degree(u) == 0:
                try:
                    fn = functions.floor_func(u) if functions else None
                    if fn is not None and int(fn.addr) != int(u):
                        base_risk[u] = 0.0
                        continue
                except Exception:
                    pass
            base_risk[u] = self._get_base_node_risk(u)

        reachable_risk: Dict[int, float] = {}
        for u in fwd_graph.nodes():
            best = base_risk.get(u, 0.0)
            try:
                for v in nx.descendants(fwd_graph, u):
                    rv = base_risk.get(v, 0.0)
                    if rv > best:
                        best = rv
            except Exception:
                pass
            reachable_risk[u] = best
        return reachable_risk

    def _score_state_priority(self, state: Any, depth: int, reachable_risk_map: Dict[int, float]) -> float:
        """
        Compute risk-prioritized state heuristic:
            H(s) = max_{v in Reachable(s)} P_GNN(v) - lambda * Depth(s)
        """
        addr = int(state.addr)
        if addr in reachable_risk_map:
            risk = reachable_risk_map[addr]
        else:
            risk = self._get_base_node_risk(addr)
            try:
                functions = self.loader.get_functions()
                fn = functions.floor_func(addr) if functions else None
                if fn is not None and fn.addr in reachable_risk_map:
                    risk = max(risk, reachable_risk_map[fn.addr])
            except Exception:
                pass
        try:
            for frame in getattr(state, "callstack", ()):
                ret_addr = getattr(frame, "ret_addr", None)
                if isinstance(ret_addr, int) and ret_addr > 0:
                    r_ret = reachable_risk_map.get(ret_addr, 0.0)
                    if r_ret > risk:
                        risk = r_ret
        except Exception:
            pass
        return float(risk) - (self.depth_penalty_lambda * float(depth))

    def get_execution_trace(self) -> List[ExecutionState]:
        if self._trace_cache is not None:
            return self._trace_cache

        import heapq
        import networkx as nx
        import claripy
        from graph.graph_builder import GraphBuilder

        t_trace_start = time.perf_counter()
        states: List[ExecutionState] = []
        step_timestamps_ms: List[float] = []
        self.engine.simgr = self.engine.project.factory.simulation_manager(self.engine.state, save_unsat=True)

        active_stash = []
        deadended_stash = []
        unsat_stash = []
        errored_stash = []

        node_to_scc = {}
        intra_loop_headers = set()
        try:
            nx_cfg = GraphBuilder(self.loader).build_networkx_cfg()
            functions = self.loader.get_functions()
            intra_cfg = nx.DiGraph()
            for u, v in nx_cfg.edges():
                if self.engine.project.is_hooked(u) or self.engine.project.is_hooked(v):
                    continue
                fn_u = functions.floor_func(u) if functions else None
                fn_v = functions.floor_func(v) if functions else None
                if fn_u is not None and fn_v is not None and fn_u.addr == fn_v.addr and not fn_u.is_plt and not fn_u.is_simprocedure:
                    intra_cfg.add_edge(u, v)
            for scc in nx.strongly_connected_components(intra_cfg):
                if len(scc) > 1:
                    for n in scc:
                        node_to_scc[n] = scc
                    for n in scc:
                        if any(pred not in scc for pred in intra_cfg.predecessors(n)):
                            intra_loop_headers.add(n)
                            break
        except Exception:
            nx_cfg = nx.DiGraph()

        reachable_risk_map: Dict[int, float] = (
            self._compute_reachable_risk_map(nx_cfg) if self.scheduler_mode == "maxheap" else {}
        )

        dfs_stack: List[Tuple[Any, Optional[ExecutionState], int, Tuple[int, ...]]] = []
        max_heap: List[Tuple[float, int, int, Any, Optional[ExecutionState], int, Tuple[int, ...]]] = []
        heap_counter = 0
        max_frontier_size = 0
        timed_out_flag = False

        def _frontier_len() -> int:
            return len(max_heap) if self.scheduler_mode == "maxheap" else len(dfs_stack)

        def _push_frontier(st_obj: Any, par_state: Optional[ExecutionState], d: int, hist: Tuple[int, ...]) -> None:
            nonlocal heap_counter, max_frontier_size
            if self.scheduler_mode == "maxheap":
                prio = self._score_state_priority(st_obj, d, reachable_risk_map)
                heap_counter += 1
                heapq.heappush(max_heap, (-prio, int(st_obj.addr), heap_counter, st_obj, par_state, d, hist))
            else:
                dfs_stack.append((st_obj, par_state, d, hist))
            curr_sz = _frontier_len()
            if curr_sz > max_frontier_size:
                max_frontier_size = curr_sz

        def _pop_frontier() -> Tuple[Any, Optional[ExecutionState], int, Tuple[int, ...]]:
            if self.scheduler_mode == "maxheap":
                _, _, _, st_obj, par_state, d, hist = heapq.heappop(max_heap)
                return st_obj, par_state, d, hist
            return dfs_stack.pop()

        _push_frontier(self.engine.state, None, 0, (self.engine.state.addr,))
        loop_pre_states = {}

        while _frontier_len() > 0 and len(states) < self.max_steps:
            if self.timeout_seconds is not None and (time.perf_counter() - t_trace_start) >= self.timeout_seconds:
                timed_out_flag = True
                self._emit("WARN", f"Trace exploration reached timeout ({self.timeout_seconds:.2f}s).")
                break
            state, parent_state, depth, path_history = _pop_frontier()
            addr = state.addr
            addr_hex = hex(addr)

            # Loop Summarization (only on genuine intra-procedural loops repeated along the current path)
            is_loop_hdr = (addr in intra_loop_headers) and (path_history.count(addr) >= 2)
            if is_loop_hdr:
                if addr not in loop_pre_states:
                    loop_pre_states[addr] = state.copy()
                else:
                    pre_state = loop_pre_states[addr]
                    loop_scc = node_to_scc.get(addr, set())
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
                            _push_frontier(state, parent_state, depth + 1, path_history + (exit_addr,))
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
                tracker = getattr(st, 'vuln_tracker', None)
                taint_set = getattr(tracker, 'taint_set', set()) if tracker else set()
                if is_tainted(pc_ast, taint_set):
                    return True
                pc_str = str(pc_ast).lower()
                if any(k in pc_str for k in ('stdin', 'taint', 'argv', 'env', 'buf_arg', 'user_input')):
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
            step_new_findings = []

            if not is_vuln_halt:
                try:
                    parent_vt = getattr(state, "vuln_tracker", None)
                    pre_finding_keys = set()
                    if parent_vt is not None:
                        pre_finding_keys = {
                            (f["instruction_address"], f["vuln_type"], len(f.get("call_stack", ())), tuple(f.get("call_stack", ())))
                            for f in getattr(parent_vt, "findings", [])
                        }

                    successors = self.engine.project.factory.successors(state)
                    flat_succs = successors.flat_successors
                    unsat_succs = successors.unsat_successors

                    # Propagate findings, extra_constraints_map, and symbolic_variables recorded on successor states
                    # during block/SimProcedure execution back onto the pre-step state's vuln_tracker.
                    if parent_vt is not None:
                        for succ_s in getattr(successors, "all_successors", flat_succs):
                            succ_vt = getattr(succ_s, "vuln_tracker", None)
                            if succ_vt is None:
                                continue
                            for k, v in getattr(succ_vt, "symbolic_variables", {}).items():
                                if k not in parent_vt.symbolic_variables:
                                    parent_vt.symbolic_variables[k] = v
                            for k, v in getattr(succ_vt, "extra_constraints_map", {}).items():
                                parent_vt.extra_constraints_map[k] = list(v)
                            for f in getattr(succ_vt, "findings", []):
                                f_key_full = (
                                    f["instruction_address"],
                                    f["vuln_type"],
                                    len(f.get("call_stack", ())),
                                    tuple(f.get("call_stack", ())),
                                )
                                if f_key_full not in pre_finding_keys:
                                    pre_finding_keys.add(f_key_full)
                                    step_new_findings.append(f)
                                    parent_vt.findings.append(f)

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
                        step_timestamps_ms.append((time.perf_counter() - t_trace_start) * 1000.0)
                        continue

                    err_vt, err_vs, err_vd = _classify_angr_error(err_msg)
                    self._emit("ERROR", f"[{err_vs}] {err_vt} at {addr_hex} in '{func_name}': {str(e)[:80]}")
                    is_real_vuln = err_vt != "SIMULATION_ERROR"
                    exec_state = ExecutionState(
                        function_name=func_name,
                        basic_block=addr_hex,
                        instruction_address=addr_hex,
                        execution_depth=depth,
                        symbolic_variables="None",
                        path_constraints="",
                        solver_status="UNSAT",
                        model_information=f"Execution error: {str(e)}",
                        explanation=f"Execution stopped at {addr_hex}: {str(e)}",
                        next_state="Errored (Simulation halted)",
                        is_library=is_lib,
                        is_branch=False,
                        raw_path_constraints="",
                        event_type="NORMAL",
                        previous_block=prev_block_hex,
                        next_block="Errored",
                        transferred_function=transferred,
                        new_constraints_introduced=False,
                        is_vulnerable=is_real_vuln,
                        vuln_type=err_vt if is_real_vuln else "",
                        vuln_severity=err_vs if is_real_vuln else "",
                        vuln_details=err_vd if is_real_vuln else "",
                    )
                    states.append(exec_state)
                    step_timestamps_ms.append((time.perf_counter() - t_trace_start) * 1000.0)
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

            if not is_vuln and step_new_findings:
                local_f = min(
                    step_new_findings,
                    key=lambda f: 0 if f["vuln_type"] in ("OOB_WRITE", "STACK_OVERFLOW", "USE_AFTER_FREE", "DOUBLE_FREE") else 1,
                )
                is_vuln = True
                vuln_type = local_f["vuln_type"]
                vuln_severity = (
                    "CRITICAL"
                    if local_f["vuln_type"] in ("OOB_WRITE", "STACK_OVERFLOW", "USE_AFTER_FREE", "DOUBLE_FREE")
                    else "HIGH"
                )
                vuln_details = local_f["details"]
                parent_vt = getattr(state, "vuln_tracker", None)
                if parent_vt is not None:
                    f_extra = local_f.get("extra_constraints")
                    if not f_extra:
                        f_extra = parent_vt.extra_constraints_map.get(
                            (local_f["instruction_address"], local_f["vuln_type"])
                        )
                    if f_extra:
                        parent_vt.extra_constraints_map[(int(addr), local_f["vuln_type"])] = list(f_extra)
                    f_copy = dict(local_f)
                    f_copy["instruction_address"] = addr_hex
                    parent_vt.findings.append(f_copy)
                self._emit("VULN", f"[{vuln_severity}] {vuln_type} mapped to {addr_hex}!")

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
            step_timestamps_ms.append((time.perf_counter() - t_trace_start) * 1000.0)

            if not succ_addrs:
                deadended_stash.append(state)
            else:
                if depth >= min(self.max_steps, 1000):
                    active_stash.append(state)
                else:
                    # Sort deterministically by address so DFS LIFO pops in ascending address order
                    ordered_succs = sorted(flat_succs, key=lambda s_st: int(s_st.addr), reverse=True)
                    for succ in ordered_succs:
                        if path_history.count(succ.addr) < 40:
                            _push_frontier(succ, exec_state, depth + 1, path_history + (succ.addr,))
                        else:
                            active_stash.append(succ)

            for succ in unsat_succs:
                unsat_stash.append(succ)

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

        elapsed_trace_ms = round((time.perf_counter() - t_trace_start) * 1000.0, 2)
        first_vuln_idx = next((i for i, s in enumerate(states) if s.is_vulnerable), None)
        self.scheduler_telemetry["states_explored"] = len(states)
        self.scheduler_telemetry["max_frontier_size"] = max_frontier_size
        self.scheduler_telemetry["elapsed_trace_ms"] = elapsed_trace_ms
        self.scheduler_telemetry["timed_out"] = timed_out_flag
        self.scheduler_telemetry["vulnerable_states_found"] = sum(1 for s in states if s.is_vulnerable)
        self.scheduler_telemetry["steps_to_first_vuln"] = (first_vuln_idx + 1) if first_vuln_idx is not None else None
        self.scheduler_telemetry["time_to_first_vuln_ms"] = (
            round(step_timestamps_ms[first_vuln_idx], 2)
            if first_vuln_idx is not None and first_vuln_idx < len(step_timestamps_ms)
            else None
        )

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
            dedup_key = (addr, state_obj.vuln_type, state_obj.previous_block)
            if dedup_key in seen_addrs:
                continue
            seen_addrs.add(dedup_key)

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

                    vars_dict = get_symbolic_variables_from_state(
                        raw_state, vars_dict, extra_constraints=extra_constraints_ast
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
                        all_c_ast = list(raw_state.solver.constraints)
                        if extra_constraints_ast:
                            all_c_ast.extend(extra_constraints_ast)

                        # First pass: variables explicitly constrained by path or safety conditions
                        for name, sym_var in vars_dict.items():
                            val = result["satisfying_assignment"].get(name)
                            if val is not None and isinstance(val, (bytes, bytearray)):
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

                        # Second pass: if path had 0 branch constraints on input (unconditional reachability),
                        # use solved assignment for primary input variable from Z3 model (never fabricate bytes).
                        if not all_bytes:
                            taint_keys = [k for k in vars_dict if k.startswith("taint_")]
                            fallback_keys = taint_keys if taint_keys else [
                                k for k in ("stdin_input", "buf_arg_0", "arg_0") if k in vars_dict
                            ]
                            for name in fallback_keys:
                                sym_var = vars_dict[name]
                                val = result["satisfying_assignment"].get(name)
                                if val is not None and isinstance(val, (bytes, bytearray)) and len(val) > 0:
                                    hex_repr = ' '.join(f'{b:02x}' for b in val)
                                    ascii_repr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in val)
                                    exploit_vars.append({
                                        "name": name,
                                        "hex": hex_repr,
                                        "ascii": ascii_repr,
                                        "raw": list(val),
                                        "constrained_bytes": [],
                                        "unconstrained_bytes": list(range(len(val))),
                                        "size": len(val),
                                    })
                                    all_bytes.extend(val)

                        if all_bytes:
                            dec_numbers = list(all_bytes)
                            py_numbers_str = str(dec_numbers)
                            reproduce_cmd = (
                                f'python3 -c "import sys; sys.stdout.buffer.write(bytes({py_numbers_str}))"'
                                f" | ./{self.original_filename}"
                            )
                            self._emit("SUCCESS", f"  Crash input computed ({len(all_bytes)} B, integers: {dec_numbers[:8]}...).")
                        else:
                            reproduce_cmd = ""
                            self._emit("WARN", "  SAT state had no concrete input buffer assignment.")
                    else:
                        reproduce_cmd = ""
                        self._emit("WARN", f"  Solver returned {solver_status}; no exploit payload synthesized.")
                except Exception as e:
                    solver_status = "ERROR"
                    reproduce_cmd = ""
                    all_bytes = bytearray()
                    exploit_vars = []
                    self._emit("ERROR", f"  Z3 error: {str(e)[:100]}")
            else:
                solver_status = "UNKNOWN"
                reproduce_cmd = ""
                all_bytes = bytearray()
                exploit_vars = []
                self._emit("WARN", f"  State registry miss for {addr} — no payload synthesized.")

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

            if solver_status == "SAT" and len(all_bytes) > 0:
                self._emit("INFO", f"  Replaying synthesized witness ({len(all_bytes)} B) against native binary...")
                crash_verification = verify_live_crash(
                    self.binary_path,
                    bytes(all_bytes),
                    vuln_type=state_obj.vuln_type,
                    is_targeted_func=bool(getattr(self, "_target_func_addr", None) is not None),
                )
                if crash_verification.get("crashed"):
                    self._emit(
                        "SUCCESS",
                        f"  Live crash verified: {crash_verification.get('signal')} via {crash_verification.get('method')}",
                    )
                else:
                    self._emit("WARN", f"  Witness did not trigger native crash: {crash_verification.get('reason')}")
            else:
                crash_verification = {
                    "attempted": False,
                    "crashed": False,
                    "returncode": None,
                    "signal": None,
                    "timed_out": False,
                    "method": "none",
                    "reason": f"No witness synthesized (solver_status={solver_status})",
                }

            exploit_verified = bool(
                solver_status == "SAT"
                and len(all_bytes) > 0
                and crash_verification.get("crashed", False)
            )

            self._emit("INFO", "  Generating fix recommendation...")
            partial_report = {
                "trace_index":        idx,
                "address":            addr,
                "function_name":      state_obj.function_name,
                "vuln_type":          state_obj.vuln_type,
                "vuln_severity":      c_info["confidence"],
                "vuln_details":       state_obj.vuln_details,
                "solver_status":      solver_status,
                "solver_time_ms":     solver_time_ms,
                "exploit_vars":       exploit_vars,
                "crash_integers":     list(all_bytes) if all_bytes else [],
                "crash_length":       len(all_bytes) if all_bytes else 0,
                "reproduce_cmd":      reproduce_cmd,
                "crash_verification": crash_verification,
                "exploit_verified":   exploit_verified,
                "confidence":         c_info["confidence"],
                "root_cause":         c_info["root_cause"],
                "impact":             c_info["impact"],
                "remediation":        c_info["remediation"],
                "disasm_hash":        _compute_block_disasm_hash(self.engine.project, addr),
                "witness_model":      {},
                "registers":          {},
                "call_stack":         [],
                "reasoning_trace":    [],
                "relevant_objects":   [],
                "smt_constraints":    [],
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
            if self.scheduler_mode == "maxheap" and (self.gnn_node_scores or self.gnn_vulnerable_functions):
                if self.gnn_vulnerable_functions and not self.gnn_node_scores:
                    flagged = [f for f in user_funcs if self.gnn_vulnerable_functions.get(f.addr, False)]
                    if flagged:
                        user_funcs = flagged
                user_funcs.sort(key=lambda f: (-self._get_base_node_risk(f.addr), int(f.addr)))
            else:
                user_funcs.sort(key=lambda f: int(f.addr))

            total_steps_used = int(self.scheduler_telemetry.get("states_explored", len(trace)))
            total_elapsed_ms = float(self.scheduler_telemetry.get("elapsed_trace_ms", 0.0))

            for ufunc in user_funcs:
                remaining_steps = self.max_steps - total_steps_used
                if remaining_steps <= 0:
                    break
                remaining_timeout = None
                if self.timeout_seconds is not None:
                    remaining_timeout = self.timeout_seconds - (total_elapsed_ms / 1000.0)
                    if remaining_timeout <= 0:
                        self.scheduler_telemetry["timed_out"] = True
                        break
                try:
                    sub_provider = AnalysisBackendProvider(
                        self.binary_path,
                        target_func_addr=ufunc.addr,
                        max_steps=min(remaining_steps, 150),
                        symbolic_input_size=self.symbolic_size,
                        gnn_vulnerable_functions=self.gnn_vulnerable_functions,
                        gnn_node_scores=self.gnn_node_scores,
                        scheduler_mode=self.scheduler_mode,
                        depth_penalty_lambda=self.depth_penalty_lambda,
                        timeout_seconds=remaining_timeout,
                        _shared_loader=self.loader,
                    )
                    sub_reports = sub_provider.scan_vulnerabilities()
                    sub_tel = sub_provider.scheduler_telemetry
                    sub_steps = int(sub_tel.get("states_explored", 0))
                    sub_ms = float(sub_tel.get("elapsed_trace_ms", 0.0))
                    if self.scheduler_telemetry["steps_to_first_vuln"] is None and sub_tel.get("steps_to_first_vuln") is not None:
                        self.scheduler_telemetry["steps_to_first_vuln"] = total_steps_used + int(sub_tel["steps_to_first_vuln"])
                        self.scheduler_telemetry["time_to_first_vuln_ms"] = round(
                            total_elapsed_ms + float(sub_tel.get("time_to_first_vuln_ms") or sub_ms), 2
                        )
                    total_steps_used += sub_steps
                    total_elapsed_ms = round(total_elapsed_ms + sub_ms, 2)
                    self.scheduler_telemetry["states_explored"] = total_steps_used
                    self.scheduler_telemetry["elapsed_trace_ms"] = total_elapsed_ms
                    self.scheduler_telemetry["max_frontier_size"] = max(
                        int(self.scheduler_telemetry.get("max_frontier_size", 0)),
                        int(sub_tel.get("max_frontier_size", 0)),
                    )
                    self.scheduler_telemetry["vulnerable_states_found"] += int(sub_tel.get("vulnerable_states_found", 0))
                    if sub_tel.get("timed_out"):
                        self.scheduler_telemetry["timed_out"] = True
                    for sr in sub_reports:
                        if not any(r["address"] == sr["address"] and r["vuln_type"] == sr["vuln_type"] for r in reports):
                            reports.append(sr)
                except Exception:
                    pass

        status_counts = {"SAT": 0, "UNSAT": 0, "UNKNOWN": 0, "TIMEOUT": 0, "ERROR": 0}
        verified_count = 0
        for rep in reports:
            st = str(rep.get("solver_status", "UNKNOWN")).upper()
            status_counts[st] = status_counts.get(st, 0) + 1
            if rep.get("exploit_verified"):
                verified_count += 1
        self.scheduler_telemetry["solver_status_counts"] = status_counts
        self.scheduler_telemetry["verified_exploits_count"] = verified_count

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
