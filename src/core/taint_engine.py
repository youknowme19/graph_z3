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
