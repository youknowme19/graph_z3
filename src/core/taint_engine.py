"""
taint_engine.py — Dynamic Data-Flow Taint Analysis

Tracks attacker-controlled (tainted) bytes from I/O sources through symbolic
memory, and detects when tainted values reach dangerous program sinks.

Operates directly on claripy bitvector symbolic ASTs — no instrumented
compilation required. Taint markers are stored in VulnerabilityTrackerPlugin
and propagated automatically via angr's symbolic state copy semantics.

Sources tracked:  read, recv, recvfrom, fgets, gets, scanf, sscanf,
                  fread, getenv, pread
Sinks tracked:    strcpy, strncpy, strcat, sprintf, snprintf, vsnprintf,
                  memcpy, memmove, system, popen, execve, execl, execvp,
                  printf (format-string), fprintf, write (data sink)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

import claripy


# ── Source / Sink catalogues ──────────────────────────────────────────────────

#: Functions that introduce attacker-controlled bytes.
#: Maps clean_name → (buf_arg_index, len_arg_index_or_None)
TAINT_SOURCES: Dict[str, Tuple[Optional[int], Optional[int]]] = {
    "read":       (1, 2),   # read(fd, buf, count)
    "pread":      (1, 2),
    "recv":       (1, 2),   # recv(sockfd, buf, len, flags)
    "recvfrom":   (1, 2),
    "fgets":      (0, 1),   # fgets(buf, size, stream)
    "gets":       (0, None),
    "fread":      (0, 2),
    "scanf":      (None, None),
    "sscanf":     (None, None),
    "getenv":     (None, None),
}

#: Dangerous sink functions.
#: Maps clean_name → (tainted_arg_indices, sink_category)
TAINT_SINKS: Dict[str, Tuple[List[int], str]] = {
    "strcpy":    ([1], "CONTROLLED_STRCPY"),
    "strncpy":   ([1], "CONTROLLED_STRNCPY"),
    "strcat":    ([1], "CONTROLLED_STRCAT"),
    "strncat":   ([1], "CONTROLLED_STRNCAT"),
    "memcpy":    ([1], "CONTROLLED_MEMCPY"),
    "memmove":   ([1], "CONTROLLED_MEMMOVE"),
    "bcopy":     ([0], "CONTROLLED_MEMCPY"),
    "printf":    ([0], "CONTROLLED_FORMAT_STRING"),
    "fprintf":   ([1], "CONTROLLED_FORMAT_STRING"),
    "sprintf":   ([1], "CONTROLLED_FORMAT_STRING"),
    "snprintf":  ([2], "CONTROLLED_FORMAT_STRING"),
    "vsnprintf": ([2], "CONTROLLED_FORMAT_STRING"),
    "system":    ([0], "CONTROLLED_CMD_INJECTION"),
    "popen":     ([0], "CONTROLLED_CMD_INJECTION"),
    "execve":    ([0], "CONTROLLED_EXEC"),
    "execl":     ([0], "CONTROLLED_EXEC"),
    "execvp":    ([0], "CONTROLLED_EXEC"),
    "execlp":    ([0], "CONTROLLED_EXEC"),
    "write":     ([1], "CONTROLLED_WRITE"),
}


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class TaintSource:
    """Records one taint introduction event."""
    func_name:  str
    call_site:  int
    buf_base:   Any
    byte_count: int
    var_names:  List[str] = field(default_factory=list)


@dataclass
class TaintSinkHit:
    """A detected taint-flow-to-sink event."""
    sink_func:      str
    sink_site:      int
    sink_category:  str
    tainted_arg:    int
    taint_sources:  List[TaintSource]
    details:        str


# ── Core taint analysis functions ─────────────────────────────────────────────

def is_tainted(expr: Any, taint_names: Set[str]) -> bool:
    """Return True if any BVS leaf in expr is a known taint variable."""
    if not hasattr(expr, "leaf_asts"):
        return False
    try:
        for leaf in expr.leaf_asts():
            if getattr(leaf, "op", None) == "BVS":
                var_name = leaf.args[0]
                if var_name in taint_names:
                    return True
                if any(var_name.startswith(t) for t in taint_names):
                    return True
    except Exception:
        pass
    return False


def get_taint_sources(expr: Any, sources: List[TaintSource]) -> List[TaintSource]:
    """Return TaintSources whose variable names appear in expr's AST."""
    if not hasattr(expr, "leaf_asts"):
        return []
    expr_var_names: Set[str] = set()
    try:
        for leaf in expr.leaf_asts():
            if getattr(leaf, "op", None) == "BVS":
                expr_var_names.add(leaf.args[0])
    except Exception:
        return []
    return [s for s in sources if any(any(vn.startswith(t) for vn in expr_var_names) for t in s.var_names)]


def inject_taint(state: Any, func_name: str, call_site: int,
                 buf_ptr: Any, length: int) -> TaintSource:
    """
    Inject `length` fresh BVS taint-marker bytes into state memory at buf_ptr.
    Records each BVS name in state.vuln_tracker.taint_set.
    """
    tracker = state.vuln_tracker
    length = min(length, 512)  # cap to avoid explosion
    var_names: List[str] = []

    for i in range(length):
        var_name = f"taint_{func_name}_{hex(call_site)}_byte{i}"
        taint_sym = claripy.BVS(var_name, 8)
        try:
            state.memory.store(buf_ptr + i, taint_sym)
        except Exception:
            break
        var_names.append(var_name)
        if isinstance(tracker.taint_set, set):
            tracker.taint_set.add(var_name)

    src = TaintSource(
        func_name=func_name,
        call_site=call_site,
        buf_base=buf_ptr,
        byte_count=len(var_names),
        var_names=var_names,
    )
    if not hasattr(tracker, "taint_sources"):
        tracker.taint_sources = []
    tracker.taint_sources.append(src)
    tracker.log(
        f"[TAINT] Injected {len(var_names)} taint bytes from '{func_name}' "
        f"at {hex(call_site)} → buf={buf_ptr}"
    )
    return src


def check_sink(state: Any, func_name: str, call_site: int,
               args: List[Any]) -> Optional[TaintSinkHit]:
    """Check whether any tainted value reaches a dangerous sink argument."""
    sink_info = TAINT_SINKS.get(func_name)
    if sink_info is None:
        return None

    tainted_arg_indices, sink_category = sink_info
    tracker = state.vuln_tracker
    taint_names: Set[str] = getattr(tracker, "taint_set", set())
    sources: List[TaintSource] = getattr(tracker, "taint_sources", [])

    for arg_idx in tainted_arg_indices:
        if arg_idx >= len(args):
            continue
        arg_expr = args[arg_idx]
        if arg_expr is None:
            continue

        # Direct expression check
        if is_tainted(arg_expr, taint_names):
            matched = get_taint_sources(arg_expr, sources)
            src_desc = ", ".join(f"'{s.func_name}'@{hex(s.call_site)}" for s in matched) or "unknown"
            details = (
                f"Taint flow: data from {src_desc} reaches sink '{func_name}' "
                f"(arg {arg_idx}) at {hex(call_site)}. Category: {sink_category}."
            )
            return TaintSinkHit(func_name, call_site, sink_category, arg_idx, matched, details)

        # Pointer dereference check — load what the pointer points to
        try:
            loaded = state.memory.load(arg_expr, 8)
            if is_tainted(loaded, taint_names):
                matched = get_taint_sources(loaded, sources)
                src_desc = ", ".join(f"'{s.func_name}'@{hex(s.call_site)}" for s in matched) or "unknown"
                details = (
                    f"Taint flow: memory at arg {arg_idx} of '{func_name}' at "
                    f"{hex(call_site)} contains data from {src_desc}. Category: {sink_category}."
                )
                return TaintSinkHit(func_name, call_site, sink_category, arg_idx, matched, details)
        except Exception:
            pass

    return None


def build_taint_flow_summary(tracker: Any) -> Dict[str, Any]:
    """Build a serialisable taint-flow summary for a tracker state."""
    sources: List[TaintSource] = getattr(tracker, "taint_sources", [])
    tainted_names: Set[str] = getattr(tracker, "taint_set", set())
    taint_findings = [
        f for f in getattr(tracker, "findings", [])
        if f.get("vuln_type", "").startswith("TAINT_")
    ]
    return {
        "tainted_var_count": len(tainted_names),
        "sources": [
            {
                "func_name": s.func_name,
                "call_site": hex(s.call_site) if isinstance(s.call_site, int) else str(s.call_site),
                "byte_count": s.byte_count,
                "var_names_sample": s.var_names[:4],
            }
            for s in sources
        ],
        "sink_hits": [
            {
                "vuln_type": f.get("vuln_type", ""),
                "site": hex(f["instruction_address"]) if isinstance(f.get("instruction_address"), int) else str(f.get("instruction_address", "")),
                "details": f.get("details", "")[:120],
            }
            for f in taint_findings
        ],
    }
