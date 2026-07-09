import angr
import copy
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

@dataclass
class MemoryObject:
    id: str                 # Unique object identifier
    start_addr: Any         # Start address expression (claripy AST or int)
    size: Any               # Symbolic or concrete size (claripy AST or int)
    origin: str             # 'heap' | 'stack' | 'global'
    allocation_site: int    # Instruction address of allocation
    lifetime_state: str = 'live'  # 'live' | 'freed'
    taint_metadata: Dict[str, Any] = field(default_factory=dict)
    allocation_constraints: List[Any] = field(default_factory=list)


class VulnerabilityTrackerPlugin(angr.SimStatePlugin):
    """
    SimStatePlugin to trace dynamic heap/stack pointer boundaries, lifetimes,
    provenance, dynamic taint flow, and register/solver evidence logs.
    """
    def __init__(self, allocations=None, freed_allocations=None, taint_set=None, taint_sources=None, reasoning_trace=None, findings=None, symbolic_variables=None, extra_constraints_map=None):
        super().__init__()
        self.allocations: Dict[str, MemoryObject] = allocations if allocations is not None else {}
        self.freed_allocations: Dict[str, MemoryObject] = freed_allocations if freed_allocations is not None else {}
        self.taint_set: set = taint_set if taint_set is not None else set()
        self.taint_sources: List[Any] = taint_sources if taint_sources is not None else []  # List[TaintSource]
        self.reasoning_trace: List[str] = reasoning_trace if reasoning_trace is not None else []
        self.findings: List[Dict[str, Any]] = findings if findings is not None else []
        self.symbolic_variables: Dict[str, Any] = symbolic_variables if symbolic_variables is not None else {}
        self.extra_constraints_map: Dict[Tuple[int, str], List[Any]] = extra_constraints_map if extra_constraints_map is not None else {}
        
        # State transient fields
        self.pending_malloc_size = None
        self.pending_calloc_num = None
        self.pending_calloc_size = None
        self.pending_realloc_ptr = None
        self.pending_realloc_size = None

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        # Deep-copy each MemoryObject so its internal lists (allocation_constraints)
        # are independent across forked states.
        alloc_copy = {k: copy.copy(v) for k, v in self.allocations.items()}
        for obj in alloc_copy.values():
            obj.allocation_constraints = list(obj.allocation_constraints)

        freed_copy = {k: copy.copy(v) for k, v in self.freed_allocations.items()}
        for obj in freed_copy.values():
            obj.allocation_constraints = list(obj.allocation_constraints)
