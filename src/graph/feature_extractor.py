import pyvex
import networkx as nx
import math
from typing import List, Optional, Set

# Instruction categories for semantic features
UNSAFE_STRING_FUNCS: Set[str] = {
    'strcpy', 'strncpy', 'strcat', 'strncat', 'sprintf', 'snprintf',
    'vsprintf', 'vsnprintf', 'gets', 'getwd', 'strcpy', 'strcat',
    'memcpy', 'memmove', 'bcopy', 'scanf', 'sscanf', 'fscanf',
    'vscanf', 'vsscanf', 'vfscanf', 'realpath', 'getopt', 'getpass',
    'streadd', 'strecpy', 'strtrns', 'strccpy'
}

FORMAT_STRING_FUNCS: Set[str] = {
    'printf', 'fprintf', 'sprintf', 'snprintf', 'vprintf', 'vfprintf',
    'vsprintf', 'vsnprintf', 'syslog', 'err', 'warn', 'verr', 'vwarn'
}

DANGEROUS_FUNCS: Set[str] = {
    'system', 'popen', 'execl', 'execlp', 'execle', 'execv', 'execvp',
    'execvpe', 'gets', 'getwd', 'strcpy', 'strcat', 'sprintf', 'vsprintf',
    'scanf', 'sscanf', 'fscanf', 'vscanf', 'vsscanf', 'vfscanf',
    'realpath', 'getopt', 'getpass', 'streadd', 'strecpy', 'strtrns'
}

MEMORY_ALLOC_FUNCS: Set[str] = {
    'malloc', 'calloc', 'realloc', 'free', 'alloca', 'valloc', 'memalign',
    'posix_memalign', 'aligned_alloc', 'reallocarray'
}

MEMORY_COPY_FUNCS: Set[str] = {
    'memcpy', 'memmove', 'memccpy', 'memset', 'bcopy', 'bzero', 'strcpy',
    'strncpy', 'strcat', 'strncat', 'strlcpy', 'strlcat'
}

CONTROL_FLOW_FUNCS: Set[str] = {
    'longjmp', 'setjmp', 'siglongjmp', 'sigsetjmp', 'exit', '_exit',
    'abort', 'atexit', 'on_exit', 'quick_exit', '_Exit'
}

def _normalize(val: float, min_val: float = 0.0, max_val: float = 100.0) -> float:
    """Normalize value to [0, 1] range with clipping."""
    if max_val == min_val:
        return 0.0
    return max(0.0, min(1.0, (val - min_val) / (max_val - min_val)))

def _log_scale(val: float, base: float = 10.0) -> float:
    """Log scale for heavy-tailed distributions."""
    if val <= 0:
        return 0.0
    return math.log(val) / math.log(base)

def _count_instructions_by_type(vex_block, opcodes: Set[str]) -> int:
    """Count instructions matching given opcodes."""
    count = 0
    try:
        for stmt in vex_block.statements:
            if hasattr(stmt, 'op') and stmt.op in opcodes:
                count += 1
    except Exception:
        pass
    return count

def _get_call_targets(vex_block) -> List[str]:
    """Extract called function names from VEX IR."""
    targets = []
    try:
        for stmt in vex_block.statements:
            if isinstance(stmt, pyvex.stmt.IMark):
                continue
            if hasattr(stmt, 'addr') and stmt.addr is not None:
                pass
    except Exception:
        pass
    return targets


def extract_node_features(node, nx_graph, loader=None, state=None) -> List[float]:
    """
    Extracts a 40-dimensional feature vector for a single basic block (node) in the CFG.
    
    Feature Groups:
    A. Structural/Topological (8) - graph position, connectivity, loops
    B. Instruction Count/Complexity (6) - size, diversity, nesting
    C. Semantic/Code Patterns (12) - dangerous APIs, memory ops, control flow
    D. Data-Flow / Memory (8) - taint, symbolic, pointers, stack/heap
    E. Symbolic Execution State (6) - constraints, variables, solver stats
    
    Total: 40 features
    """
    addr = node.addr if hasattr(node, 'addr') else 0
    
    # ============================================================
    # A. STRUCTURAL / TOPOLOGICAL FEATURES (8)
    # ============================================================
    in_degree = nx_graph.in_degree(addr) if nx_graph.has_node(addr) else 0
    out_degree = nx_graph.out_degree(addr) if nx_graph.has_node(addr) else 0
    
    # Depth from entry (updated post-hoc by update_graph_features)
    depth_from_entry = 0.0
    if nx_graph.has_node(addr):
        depth_from_entry = float(nx_graph.nodes[addr].get('depth_from_entry', 0.0))
    
    is_loop_header = 1.0 if nx_graph.has_node(addr) and nx_graph.nodes[addr].get('is_loop_header', False) else 0.0
    
    # Strongly connected component size (loop nesting indicator)
    scc_size = 0.0
    if nx_graph.has_node(addr):
        try:
            for scc in nx.strongly_connected_components(nx_graph):
                if addr in scc:
                    scc_size = float(len(scc))
                    break
        except Exception:
            pass
    
    # Dominator tree depth (approx: number of unique paths from entry)
    num_predecessors = float(in_degree)
    num_successors = float(out_degree)
    
    # Betweenness centrality proxy: in_degree * out_degree
    flow_centrality = float(in_degree * out_degree)
    
    # Post-dominance: reverse graph out-degree (exits)
    exit_degree = 0.0
    try:
        rev_graph = nx_graph.reverse()
        if rev_graph.has_node(addr):
            exit_degree = float(rev_graph.out_degree(addr))
    except Exception:
        pass
    
    # Is entry/exit block
    is_entry_block = 1.0 if nx_graph.has_node(addr) and nx_graph.in_degree(addr) == 0 else 0.0
    is_exit_block = 1.0 if nx_graph.has_node(addr) and nx_graph.out_degree(addr) == 0 else 0.0
    
    # ============================================================
    # B. INSTRUCTION COUNT / COMPLEXITY (6)
    # ============================================================
    num_instructions = len(node.instruction_addrs) if hasattr(node, 'instruction_addrs') and node.instruction_addrs else 0
    
    # Initialize block variable
    block = None
    try:
        block = node.block
    except Exception:
        pass
    
    # Instruction diversity (unique mnemonics)
    unique_mnemonics = 0
    mnemonic_set = set()
    total_vex_stmts = 0
    try:
        if block and block.vex:
            for stmt in block.vex.statements:
                total_vex_stmts += 1
                if isinstance(stmt, pyvex.stmt.IMark):
                    # Try to get mnemonic from Capstone
                    pass
    except Exception:
        pass
    
    # VEX statement counts by type
    vex_istore = 0
    vex_iload = 0
    vex_iop = 0
    vex_imark = 0
    try:
        if block and block.vex:
            for stmt in block.vex.statements:
                tag = stmt.tag if hasattr(stmt, 'tag') else ''
                if 'Ist_Store' in str(tag):
                    vex_istore += 1
                elif 'Ist_Load' in str(tag):
                    vex_iload += 1
                elif 'Ist_WrTmp' in str(tag) or 'Ist_Put' in str(tag):
                    vex_iop += 1
                elif 'Ist_IMark' in str(tag):
                    vex_imark += 1
    except Exception:
        pass
    
    # ============================================================
    # C. SEMANTIC / CODE PATTERNS (12)
    # ============================================================
    # These are detected via VEX IR and function name heuristics
    has_unsafe_string = 0.0
    has_format_string = 0.0
    has_dangerous_call = 0.0
    has_memory_alloc = 0.0
    has_memory_copy = 0.0
    has_control_flow = 0.0
    has_syscall = 0.0
    has_simprocedure = 0.0
    
    # Memory operation signatures
    has_stack_write = 0.0
    has_heap_write = 0.0
    has_global_write = 0.0
    has_memory_write = 0.0  # Initialize to avoid unbound error
    
    # Pointer arithmetic / array indexing patterns
    has_pointer_arith = 0.0
    has_array_index = 0.0
    
    # Integer arithmetic that could overflow
    has_int_arith = 0.0
    has_comparison = 0.0
    
    try:
        block = node.block
        if block:
            # Check function name for known patterns
            func_name = getattr(node, 'name', '') or ''
            func_name_lower = func_name.lower()
            
            if any(uf in func_name_lower for uf in UNSAFE_STRING_FUNCS):
                has_unsafe_string = 1.0
            if any(ff in func_name_lower for ff in FORMAT_STRING_FUNCS):
                has_format_string = 1.0
            if any(df in func_name_lower for df in DANGEROUS_FUNCS):
                has_dangerous_call = 1.0
            if any(ma in func_name_lower for ma in MEMORY_ALLOC_FUNCS):
                has_memory_alloc = 1.0
            if any(mc in func_name_lower for mc in MEMORY_COPY_FUNCS):
                has_memory_copy = 1.0
            if any(cf in func_name_lower for cf in CONTROL_FLOW_FUNCS):
                has_control_flow = 1.0
            
            # VEX-level analysis
            if block.vex:
                for stmt in block.vex.statements:
                    tag = str(stmt.tag) if hasattr(stmt, 'tag') else ''
                    
                    # Memory writes by type
                    if 'Ist_Store' in tag:
                        # Could be stack, heap, or global - approximate via address
                        has_memory_write = 1.0  # Keep existing
                        # We'd need state to distinguish stack vs heap vs global
                    
                    # Integer arithmetic
                    if hasattr(stmt, 'data') and hasattr(stmt.data, 'op'):
                        op = str(stmt.data.op)
                        if any(x in op for x in ['Add', 'Sub', 'Mul', 'Div', 'Mod']):
                            has_int_arith = 1.0
                        if any(x in op for x in ['Cmp', 'CmpNE', 'CmpEQ', 'CmpLT', 'CmpLE', 'CmpGT', 'CmpGE']):
                            has_comparison = 1.0
                    
                    # Pointer arithmetic (address calculations)
                    if hasattr(stmt, 'addr') and stmt.addr is not None:
                        # Could add more sophisticated analysis
                        pass
                        
    except Exception:
        pass
    
    # Syscall / SimProcedure flags
    is_library_call = 1.0 if getattr(node, 'is_simprocedure', False) or getattr(node, 'is_syscall', False) else 0.0
    has_syscall = 1.0 if getattr(node, 'is_syscall', False) else 0.0
    has_simprocedure = 1.0 if getattr(node, 'is_simprocedure', False) else 0.0
    
    # ============================================================
    # D. DATA-FLOW / MEMORY FEATURES (8)
    # ============================================================
    # These require symbolic state; default to 0 if unavailable
    num_symbolic_variables = 0.0
    num_path_constraints = 0.0
    has_symbolic_store_addr = 0.0
    has_symbolic_load_addr = 0.0
    has_symbolic_branch = 0.0
    has_tainted_input = 0.0
    taint_byte_count = 0.0
    stack_depth = 0.0
    
    if state:
        try:
            num_path_constraints = float(len(state.solver.constraints))
            num_symbolic_variables = float(len(state.solver.variables))
            
            # Check for symbolic branch condition
            if hasattr(state, 'history') and state.history.jumpkind in ('Ijk_Boring', 'Ijk_Call', 'Ijk_Ret'):
                # Would need to check if the branch condition is symbolic
                pass
            
            # Taint tracking from vuln_plugin
            if hasattr(state, 'vuln_tracker'):
                tracker = state.vuln_tracker
                if hasattr(tracker, 'taint_set') and tracker.taint_set:
                    has_tainted_input = 1.0
                    taint_byte_count = float(len(tracker.taint_set))
            
            # Stack depth approximation
            try:
                sp = state.regs.sp
                if hasattr(sp, 'concrete'):
                    stack_depth = float(sp.concrete) if sp.concrete else 0.0
            except Exception:
                pass
                
        except Exception:
            pass
    
    # ============================================================
    # E. SYMBOLIC EXECUTION STATE (6) - require state
    # ============================================================
    avg_constraint_complexity = 0.0
    max_constraint_depth = 0.0
    num_unique_variables = 0.0
    has_concrete_model = 0.0
    solver_time_estimate = 0.0
    path_satisfiability = 1.0  # assume SAT unless proven otherwise
    
    if state:
        try:
            constraints = list(state.solver.constraints)
            if constraints:
                # Estimate constraint complexity by AST size
                total_size = sum(len(str(c)) for c in constraints)
                avg_constraint_complexity = float(total_size / len(constraints))
                
                # Max depth of any constraint AST
                max_constraint_depth = float(max(len(str(c)) for c in constraints))
                
                # Unique symbolic variables across all constraints
                var_names = set()
                for c in constraints:
                    if hasattr(c, 'leaf_asts'):
                        for leaf in c.leaf_asts():
                            if hasattr(leaf, 'op') and leaf.op == 'BVS':
                                var_names.add(leaf.args[0])
                num_unique_variables = float(len(var_names))
                
                # Check if solver has a concrete model
                if state.solver.satisfiable():
                    has_concrete_model = 1.0
                else:
                    path_satisfiability = 0.0
                    
        except Exception:
            pass
    
    # ============================================================
    # ASSEMBLE 40-DIMENSIONAL FEATURE VECTOR
    # ============================================================
    features = [
        # A. Structural/Topological (8)
        _normalize(in_degree, 0, 20),           # 0: in_degree
        _normalize(out_degree, 0, 20),          # 1: out_degree
        _normalize(depth_from_entry, 0, 500),   # 2: depth_from_entry
        is_loop_header,                          # 3: is_loop_header
        _normalize(scc_size, 1, 50),            # 4: scc_size
        _normalize(num_predecessors, 0, 20),    # 5: num_predecessors
        _normalize(num_successors, 0, 20),      # 6: num_successors
        _normalize(flow_centrality, 0, 400),    # 7: flow_centrality
        
        # B. Instruction Count/Complexity (6)
        _normalize(num_instructions, 0, 100),   # 8: num_instructions
        _normalize(vex_imark, 0, 50),           # 9: vex_imark (instruction markers)
        _normalize(vex_istore, 0, 20),          # 10: vex_istore
        _normalize(vex_iload, 0, 20),           # 11: vex_iload
        _normalize(vex_iop, 0, 100),            # 12: vex_iop (operations)
        _log_scale(float(total_vex_stmts + 1)), # 13: total_vex_stmts (log)
        
        # C. Semantic/Code Patterns (12)
        is_library_call,                         # 14: is_library_call
        has_syscall,                             # 15: has_syscall
        has_simprocedure,                        # 16: has_simprocedure
        has_unsafe_string,                       # 17: has_unsafe_string
        has_format_string,                       # 18: has_format_string
        has_dangerous_call,                      # 19: has_dangerous_call
        has_memory_alloc,                        # 20: has_memory_alloc
        has_memory_copy,                         # 21: has_memory_copy
        has_control_flow,                        # 22: has_control_flow
        has_int_arith,                           # 23: has_int_arith
        has_comparison,                          # 24: has_comparison
        has_memory_write,                        # 25: has_memory_write (from original)
        
        # D. Data-Flow / Memory (8)
        _normalize(num_symbolic_variables, 0, 100),    # 26: num_symbolic_variables
        _normalize(num_path_constraints, 0, 500),      # 27: num_path_constraints
        has_symbolic_store_addr,                        # 28: has_symbolic_store_addr
        has_symbolic_load_addr,                         # 29: has_symbolic_load_addr
        has_symbolic_branch,                            # 30: has_symbolic_branch
        has_tainted_input,                              # 31: has_tainted_input
        _normalize(taint_byte_count, 0, 256),          # 32: taint_byte_count
        _normalize(stack_depth, 0, 100000),            # 33: stack_depth (normalized)
        
        # E. Symbolic Execution State (6)
        _normalize(avg_constraint_complexity, 0, 10000), # 34: avg_constraint_complexity
        _normalize(max_constraint_depth, 0, 5000),       # 35: max_constraint_depth
        _normalize(num_unique_variables, 0, 50),         # 36: num_unique_variables
        has_concrete_model,                               # 37: has_concrete_model
        _normalize(solver_time_estimate, 0, 10000),      # 38: solver_time_estimate
        path_satisfiability,                              # 39: path_satisfiability
    ]
    
    # Sanity check: exactly 40 features
    assert len(features) == 40, f"Expected 40 features, got {len(features)}"
    
    return features


def update_graph_features(nx_graph, entry_addr=None):
    """
    Post-process the networkx graph to update structural features that require the full graph.
    Updates: depth_from_entry, in_degree, out_degree, is_loop_header, and new features.
    """
    # Compute depth from entry for all reachable nodes
    if entry_addr is not None and nx_graph.has_node(entry_addr):
        try:
            paths = nx.single_source_shortest_path_length(nx_graph, entry_addr)
            for node, dist in paths.items():
                if 'features' in nx_graph.nodes[node]:
                    nx_graph.nodes[node]['features'][2] = _normalize(dist, 0, 500)  # depth_from_entry
                    nx_graph.nodes[node]['depth_from_entry'] = float(dist)
        except Exception:
            pass
    
    # Update per-node features that depend on full graph
    for node in nx_graph.nodes():
        if 'features' not in nx_graph.nodes[node]:
            continue
            
        # Update degrees
        nx_graph.nodes[node]['features'][0] = _normalize(nx_graph.in_degree(node), 0, 20)
        nx_graph.nodes[node]['features'][1] = _normalize(nx_graph.out_degree(node), 0, 20)
        
        # Loop header
        is_loop_header = 1.0 if nx_graph.nodes[node].get('is_loop_header', False) else 0.0
        nx_graph.nodes[node]['features'][3] = is_loop_header
        
        # SCC size
        try:
            scc_size = 0.0
            for scc in nx.strongly_connected_components(nx_graph):
                if node in scc:
                    scc_size = float(len(scc))
                    break
            nx_graph.nodes[node]['features'][4] = _normalize(scc_size, 1, 50)
        except Exception:
            pass
        
        # Flow centrality = in_deg * out_deg
        in_d = nx_graph.in_degree(node)
        out_d = nx_graph.out_degree(node)
        nx_graph.nodes[node]['features'][7] = _normalize(in_d * out_d, 0, 400)


# ============================================================
# FEATURE NAMES FOR INTERPRETABILITY / DEBUGGING
# ============================================================

FEATURE_NAMES = [
    # A. Structural/Topological (8)
    "in_degree",
    "out_degree", 
    "depth_from_entry",
    "is_loop_header",
    "scc_size",
    "num_predecessors",
    "num_successors",
    "flow_centrality",
    
    # B. Instruction Count/Complexity (6)
    "num_instructions",
    "vex_imark",
    "vex_istore",
    "vex_iload", 
    "vex_iop",
    "total_vex_stmts_log",
    
    # C. Semantic/Code Patterns (12)
    "is_library_call",
    "has_syscall",
    "has_simprocedure",
    "has_unsafe_string",
    "has_format_string",
    "has_dangerous_call",
    "has_memory_alloc",
    "has_memory_copy",
    "has_control_flow",
    "has_int_arith",
    "has_comparison",
    "has_memory_write",
    
    # D. Data-Flow / Memory (8)
    "num_symbolic_variables",
    "num_path_constraints",
    "has_symbolic_store_addr",
    "has_symbolic_load_addr",
    "has_symbolic_branch",
    "has_tainted_input",
    "taint_byte_count",
    "stack_depth",
    
    # E. Symbolic Execution State (6)
    "avg_constraint_complexity",
    "max_constraint_depth",
    "num_unique_variables",
    "has_concrete_model",
    "solver_time_estimate",
    "path_satisfiability",
]

FEATURE_GROUPS = {
    "structural": list(range(0, 8)),
    "instruction": list(range(8, 14)),
    "semantic": list(range(14, 26)),
    "dataflow": list(range(26, 34)),
    "symbolic": list(range(34, 40)),
}

assert len(FEATURE_NAMES) == 40
assert sum(len(v) for v in FEATURE_GROUPS.values()) == 40