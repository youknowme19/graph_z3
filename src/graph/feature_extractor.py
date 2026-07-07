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
    
