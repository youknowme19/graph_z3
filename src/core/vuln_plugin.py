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

        c = VulnerabilityTrackerPlugin(
            allocations=alloc_copy,
            freed_allocations=freed_copy,
            taint_set=copy.copy(self.taint_set),
            taint_sources=copy.copy(self.taint_sources),
            reasoning_trace=copy.copy(self.reasoning_trace),
            # Copy each finding dict so mutations in one fork don't affect another
            findings=[dict(f) for f in self.findings],
            symbolic_variables=copy.copy(self.symbolic_variables),
            extra_constraints_map={k: list(v) for k, v in self.extra_constraints_map.items()}
        )
        c.pending_malloc_size = self.pending_malloc_size
        c.pending_calloc_num = self.pending_calloc_num
        c.pending_calloc_size = self.pending_calloc_size
        c.pending_realloc_ptr = self.pending_realloc_ptr
        c.pending_realloc_size = self.pending_realloc_size
        return c

    def add_allocation(self, id_str: str, addr: Any, size: Any, origin: str, site: int, constraints: List[Any] = None):
        obj = MemoryObject(
            id=id_str,
            start_addr=addr,
            size=size,
            origin=origin,
            allocation_site=site,
            lifetime_state='live',
            allocation_constraints=constraints or []
        )
        self.allocations[id_str] = obj
        self.log(f"Allocation added: {id_str} at {self._hex(addr)} (size {size}, type {origin})")

    def free_allocation(self, id_str: str, site: int):
        if id_str in self.allocations:
            obj = self.allocations.pop(id_str)
            obj.lifetime_state = 'freed'
            self.freed_allocations[id_str] = obj
            self.log(f"Allocation freed: {id_str} at {self._hex(obj.start_addr)} (size {obj.size})")

    def log(self, msg: str):
        self.reasoning_trace.append(msg)

    def _hex(self, val):
        if isinstance(val, int):
            return hex(val)
        try:
            if hasattr(val, 'args') and isinstance(val.args[0], int):
                return hex(val.args[0])
        except Exception:
            pass
        return str(val)
