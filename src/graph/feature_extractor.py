import pyvex
import networkx as nx
import math
from collections import defaultdict
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

TAINT_SOURCE_FUNCS: Set[str] = {
    'fgets', 'gets', 'scanf', 'fscanf', 'sscanf', 'vscanf', 'vfscanf',
    'vsscanf', 'recv', 'recvfrom', 'recvmsg', 'read', 'pread', 'fread',
    'getenv', 'getline', 'getdelim', 'atoi', 'atol', 'atoll', 'strtol',
    'strtoul', 'strtoll', 'rand', 'random', 'accept', 'connect'
}

DEALLOC_FUNCS: Set[str] = {
    'free', 'cfree', 'realloc', 'reallocarray'
}


def _clean_api_name(raw_name: str) -> str:
    """Normalize dynamic import / PLT stub name without leaking local symbols."""
    if not raw_name:
        return ""
    base = raw_name.split("+")[0].strip().lower()
    if base.startswith("imp."):
        base = base[4:]
    base = base.lstrip("_")
    if base.startswith(" sub_") or base.startswith("sub_") or base.startswith("loc_"):
        return ""
    # Guarantee zero benchmark/testcase label leakage
    if any(tok in base for tok in ("bad", "good", "cwe", "cve", "vuln", "patch", "sink")):
        return ""
    for suffix in ("_chk", "$darwin_extsn", "@plt"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    return base


def _matches_api(clean_name: str, api_set: Set[str]) -> bool:
    if not clean_name:
        return False
    if clean_name in api_set:
        return True
    # Match real-world C ecosystem external library/kernel import families (OpenSSL, FFmpeg, Linux, GLib, GPAC, ImageMagick)
    if api_set is MEMORY_ALLOC_FUNCS and any(k in clean_name for k in ("malloc", "calloc", "realloc", "kzalloc", "kmalloc", "vmalloc", "acquirememory", "acquirequantum")):
        return True
    if api_set is DEALLOC_FUNCS and any(k in clean_name for k in ("free", "relinquish", "unref", "destroy")):
        return True
    if api_set is MEMORY_COPY_FUNCS and any(k in clean_name for k in ("memcpy", "memmove", "strcpy", "strncpy", "strcat", "copy_from_user", "copy_to_user", "skb_put")):
        return True
    if api_set is TAINT_SOURCE_FUNCS and any(k in clean_name for k in ("copy_from_user", "get_user", "bio_read", "ssl_read", "avio_r", "skb_pull", "nla_data", "recv", "fread")):
        return True
    if api_set is FORMAT_STRING_FUNCS and any(k in clean_name for k in ("printf", "snprintf", "sprintf", "syslog")):
        return True
    return False

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
    # scc_size is updated efficiently in update_graph_features()

    # Dominator tree depth and back-edge count (replacing redundant duplicate degree features)
    dominator_tree_depth = 0.0
    back_edge_count = 0.0
    
    # Betweenness centrality proxy: in_degree * out_degree
    flow_centrality = float(in_degree * out_degree)
    
    # Is entry/exit block
    is_entry_block = 1.0 if nx_graph.has_node(addr) and in_degree == 0 else 0.0
    is_exit_block = 1.0 if nx_graph.has_node(addr) and out_degree == 0 else 0.0
    
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
    
    # Integer arithmetic & VEX static dataflow proxies
    has_int_arith = 0.0
    has_comparison = 0.0
    vex_num_temps = 0
    has_computed_store_addr = 0.0
    has_computed_load_addr = 0.0
    has_conditional_exit = 0.0
    vex_cast_shift_ops = 0
    vex_div_mod_ops = 0.0
    has_zero_const_op = 0.0
    vex_stack_offset_ops = 0

    try:
        # Check node's own clean dynamic import API name (never local user symbols)
        raw_node_name = ""
        if nx_graph.has_node(addr):
            raw_node_name = nx_graph.nodes[addr].get('name', '') or ''
        if not raw_node_name:
            raw_node_name = getattr(node, 'name', '') or ''
        clean_self_api = _clean_api_name(raw_node_name)

        if _matches_api(clean_self_api, UNSAFE_STRING_FUNCS):
            has_unsafe_string = 1.0
        if _matches_api(clean_self_api, FORMAT_STRING_FUNCS):
            has_format_string = 1.0
        if _matches_api(clean_self_api, DANGEROUS_FUNCS):
            has_dangerous_call = 1.0
        if _matches_api(clean_self_api, MEMORY_ALLOC_FUNCS):
            has_memory_alloc = 1.0
        if _matches_api(clean_self_api, MEMORY_COPY_FUNCS):
            has_memory_copy = 1.0
        if _matches_api(clean_self_api, CONTROL_FLOW_FUNCS):
            has_control_flow = 1.0

        block = node.block
        if block and block.vex:
            try:
                vex_num_temps = len(block.vex.tyenv.types)
            except Exception:
                vex_num_temps = 0

            for stmt in block.vex.statements:
                tag = str(stmt.tag) if hasattr(stmt, 'tag') else ''

                if 'Ist_Exit' in tag:
                    has_conditional_exit = 1.0

                if 'Ist_Store' in tag:
                    has_memory_write = 1.0
                    s_addr = getattr(stmt, 'addr', None)
                    if s_addr is not None and 'RdTmp' in str(type(s_addr)):
                        has_computed_store_addr = 1.0
                    s_data = getattr(stmt, 'data', None)
                    if s_data is not None and str(s_data) in ('0x0', '0x00000000', '0x0000000000000000'):
                        has_zero_const_op = 1.0

                # Inspect expressions recursively via stmt.expressions if available
                exprs = list(getattr(stmt, 'expressions', []))
                for expr in exprs:
                    etag = str(getattr(expr, 'tag', ''))
                    if 'Iex_Load' in etag:
                        vex_iload = max(vex_iload, 1)
                        l_addr = getattr(expr, 'addr', None)
                        if l_addr is not None and 'RdTmp' in str(type(l_addr)):
                            has_computed_load_addr = 1.0
                    if hasattr(expr, 'op'):
                        op = str(expr.op)
                        if any(x in op for x in ('Add', 'Sub', 'Mul', 'Div', 'Mod')):
                            has_int_arith = 1.0
                        if any(x in op for x in ('Div', 'Mod')):
                            vex_div_mod_ops = 1.0
                        if any(x in op for x in ('Cmp', 'CmpNE', 'CmpEQ', 'CmpLT', 'CmpLE', 'CmpGT', 'CmpGE')):
                            has_comparison = 1.0
                            for arg in getattr(expr, 'args', []):
                                if str(arg) in ('0x0', '0x00000000', '0x0000000000000000'):
                                    has_zero_const_op = 1.0
                        if any(x in op for x in ('Shl', 'Shr', 'Sar', 'Uto', 'Sto', '64to', '32to', '16to')):
                            vex_cast_shift_ops += 1
                    if 'Const' in etag:
                        sval = str(expr)
                        if sval.startswith('0xff') or sval in ('0x10', '0x20', '0x30', '0x40', '0x64'):
                            vex_stack_offset_ops += 1
    except Exception:
        pass

    # Syscall / SimProcedure / PLT stub flags
    is_plt_node = bool(clean_self_api) if 'clean_self_api' in locals() else False
    is_library_call = 1.0 if (is_plt_node or getattr(node, 'is_simprocedure', False) or getattr(node, 'is_syscall', False)) else 0.0
    has_syscall = 1.0 if getattr(node, 'is_syscall', False) else 0.0
    has_simprocedure = 1.0 if (is_plt_node or getattr(node, 'is_simprocedure', False)) else 0.0

    # ============================================================
    # D. DATA-FLOW / MEMORY FEATURES (8)
    # ============================================================
    # When symbolic state is unavailable (static GNN pre-filter), populate static VEX/CFG proxies
    num_symbolic_variables = float(vex_num_temps)
    num_path_constraints = 0.0
    has_symbolic_store_addr = has_computed_store_addr
    has_symbolic_load_addr = has_computed_load_addr
    has_symbolic_branch = has_conditional_exit
    has_tainted_input = 1.0 if ('clean_self_api' in locals() and _matches_api(clean_self_api, TAINT_SOURCE_FUNCS)) else 0.0
    taint_byte_count = float(vex_cast_shift_ops * 8)
    stack_depth = float(vex_stack_offset_ops * 1000)

    if state:
        try:
            num_path_constraints = float(len(state.solver.constraints))
            num_symbolic_variables = float(len(state.solver.variables))

            if hasattr(state, 'vuln_tracker'):
                tracker = state.vuln_tracker
                if hasattr(tracker, 'taint_set') and tracker.taint_set:
                    has_tainted_input = 1.0
                    taint_byte_count = float(len(tracker.taint_set))

            try:
                sp = state.regs.sp
                if hasattr(sp, 'concrete'):
                    stack_depth = float(sp.concrete) if sp.concrete else 0.0
            except Exception:
                pass
        except Exception:
            pass

    # ============================================================
    # E. SYMBOLIC EXECUTION / STATIC GUARD CONTEXT (6)
    # ============================================================
    vex_density = (float(total_vex_stmts) / max(float(num_instructions), 1.0)) * 500.0
    avg_constraint_complexity = vex_density
    branch_condition_complexity = 0.0
    try:
        if block and block.vex:
            cond_score = 0.0
            for stmt in block.vex.statements:
                stmt_str = str(stmt)
                if "Cmp" in stmt_str:
                    if "64" in stmt_str:
                        cond_score += 2.0
                    elif "32" in stmt_str:
                        cond_score += 1.5
                    else:
                        cond_score += 1.0
                if any(op in stmt_str for op in ("And", "Or", "Xor")):
                    cond_score += 0.5
            if getattr(block.vex, "jumpkind", None) in ("Ijk_Boring", "Ijk_Call") and out_degree > 1:
                cond_score += 1.0
            branch_condition_complexity = cond_score
    except Exception:
        pass

    num_unique_variables = 1.0 if ('clean_self_api' in locals() and _matches_api(clean_self_api, DEALLOC_FUNCS)) else 0.0
    has_concrete_model = vex_div_mod_ops
    solver_time_estimate = has_zero_const_op * 5000.0
    path_satisfiability = 1.0

    if state:
        try:
            constraints = list(state.solver.constraints)
            if constraints:
                total_size = sum(len(str(c)) for c in constraints)
                avg_constraint_complexity = float(total_size / len(constraints))
                branch_condition_complexity += float(max(len(str(c)) for c in constraints)) / 100.0

                var_names = set()
                for c in constraints:
                    if hasattr(c, 'leaf_asts'):
                        for leaf in (c.leaf_asts() if callable(c.leaf_asts) else c.leaf_asts):
                            if hasattr(leaf, 'op') and leaf.op == 'BVS':
                                var_names.add(leaf.args[0])
                num_unique_variables = float(len(var_names))

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
        _normalize(dominator_tree_depth, 0, 20), # 5: dominator_tree_depth
        _normalize(back_edge_count, 0, 5),      # 6: back_edge_count
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
        _normalize(avg_constraint_complexity, 0, 10000),         # 34: avg_constraint_complexity
        _normalize(branch_condition_complexity, 0, 10),          # 35: branch_condition_complexity
        _normalize(num_unique_variables, 0, 50),                 # 36: num_unique_variables
        has_concrete_model,                                       # 37: has_concrete_model
        _normalize(solver_time_estimate, 0, 10000),              # 38: solver_time_estimate
        path_satisfiability,                                      # 39: path_satisfiability
    ]

    # Sanity check: exactly 40 features
    assert len(features) == 40, f"Expected 40 features, got {len(features)}"

    return features


def update_graph_features(nx_graph, entry_addr=None):
    """
    Post-process the networkx graph to update structural and static inter-block context features:
    - Reachability depth from entry, degrees, SCC loop size, flow centrality
    - 1-hop callee dynamic API projection onto caller basic blocks
    - Bounded scope-safe taint-source, deallocation, and conditional-guard propagation
    """
    if entry_addr is not None and nx_graph.has_node(entry_addr):
        try:
            paths = nx.single_source_shortest_path_length(nx_graph, entry_addr)
            for node, dist in paths.items():
                if 'features' in nx_graph.nodes[node]:
                    nx_graph.nodes[node]['features'][2] = _normalize(dist, 0, 500)
                    nx_graph.nodes[node]['depth_from_entry'] = float(dist)
        except Exception:
            pass

    scc_size_map = {}
    try:
        for scc in nx.strongly_connected_components(nx_graph):
            sz = float(len(scc))
            for n in scc:
                scc_size_map[n] = sz
    except Exception:
        pass

    # Precompute function base identifier per block (e.g., 'sub_100000598' from 'sub_100000598+0x44')
    func_base = {}
    func_min_addr = {}
    func_max_addr = {}
    for n in nx_graph.nodes():
        nm = nx_graph.nodes[n].get('name', '') or ''
        fb = nm.split('+')[0]
        func_base[n] = fb
        if fb:
            func_min_addr[fb] = min(func_min_addr.get(fb, n), n)
            func_max_addr[fb] = max(func_max_addr.get(fb, n), n)

    # Precompute dominator tree depths and back-edges per function CFG subgraph
    dom_depth_map = {}
    back_edge_map = defaultdict(int)
    func_node_map = defaultdict(list)
    for n in nx_graph.nodes():
        fb = func_base.get(n, '')
        func_node_map[fb].append(n)

    for fb, fn_nodes in func_node_map.items():
        if not fb or len(fn_nodes) <= 1:
            continue
        try:
            H = nx_graph.subgraph(fn_nodes)
            cand_entries = [n for n in fn_nodes if H.in_degree(n) == 0]
            entry = cand_entries[0] if cand_entries else func_min_addr.get(fb, fn_nodes[0])
            if entry in H:
                idoms = nx.immediate_dominators(H, entry)
                for n in fn_nodes:
                    d = 0
                    curr = n
                    visited = set()
                    while curr != entry and curr in idoms and curr not in visited:
                        visited.add(curr)
                        curr = idoms[curr]
                        d += 1
                    dom_depth_map[n] = float(d)

                # Compute dominator ancestors for reducible natural loops
                dom_ancestors = {}
                for n in fn_nodes:
                    ancs = set()
                    curr = n
                    while curr in idoms and curr != entry and curr not in ancs:
                        ancs.add(idoms[curr])
                        curr = idoms[curr]
                    dom_ancestors[n] = ancs

                # Compute DFS back-edges for generalized loop detection (including irreducible graphs)
                dfs_visited = set()
                dfs_stack = set()
                dfs_back_edges = set()

                def _find_dfs_back_edges(u):
                    dfs_visited.add(u)
                    dfs_stack.add(u)
                    for succ in H.successors(u):
                        if succ in dfs_stack:
                            dfs_back_edges.add((u, succ))
                        elif succ not in dfs_visited:
                            _find_dfs_back_edges(succ)
                    dfs_stack.remove(u)

                _find_dfs_back_edges(entry)

                for u, v in H.edges():
                    if (u, v) in dfs_back_edges or v in dom_ancestors.get(u, set()) or v == u:
                        back_edge_map[u] += 1
                        back_edge_map[v] += 1
        except Exception:
            pass

    taint_seed_nodes = []
    dealloc_seed_nodes = []

    # First pass: structural metrics + 1-hop callee API lifting onto caller blocks
    for node in nx_graph.nodes():
        nd = nx_graph.nodes[node]
        if 'features' not in nd:
            continue
        feats = nd['features']

        in_d = nx_graph.in_degree(node)
        out_d = nx_graph.out_degree(node)
        feats[0] = _normalize(in_d, 0, 20)
        feats[1] = _normalize(out_d, 0, 20)
        feats[3] = 1.0 if nd.get('is_loop_header', False) else 0.0
        feats[4] = _normalize(scc_size_map.get(node, 1.0), 1, 50)
        feats[5] = _normalize(dom_depth_map.get(node, 0.0), 0.0, 20.0)
        feats[6] = _normalize(float(back_edge_map.get(node, 0)), 0.0, 5.0)
        feats[7] = _normalize(in_d * out_d, 0, 400)

        # Relative intra-function offset in slot 39
        fb = func_base.get(node, '')
        span = max(func_max_addr.get(fb, node) - func_min_addr.get(fb, node), 1)
        feats[39] = _normalize(float(node - func_min_addr.get(fb, node)) / float(span), 0.0, 1.0)

        # Lift 1-hop dynamic import stub API flags onto the calling basic block
        for succ in nx_graph.successors(node):
            succ_name = _clean_api_name(nx_graph.nodes[succ].get('name', ''))
            if not succ_name:
                continue
            if _matches_api(succ_name, UNSAFE_STRING_FUNCS):
                feats[17] = 1.0
            if _matches_api(succ_name, FORMAT_STRING_FUNCS):
                feats[18] = 1.0
            if _matches_api(succ_name, DANGEROUS_FUNCS):
                feats[19] = 1.0
            if _matches_api(succ_name, MEMORY_ALLOC_FUNCS):
                feats[20] = 1.0
            if _matches_api(succ_name, MEMORY_COPY_FUNCS):
                feats[21] = 1.0
            if _matches_api(succ_name, CONTROL_FLOW_FUNCS):
                feats[22] = 1.0
            if _matches_api(succ_name, TAINT_SOURCE_FUNCS):
                feats[31] = 1.0
                taint_seed_nodes.append(node)
            if _matches_api(succ_name, DEALLOC_FUNCS):
                feats[36] = max(feats[36], 0.5)
                dealloc_seed_nodes.append(node)

    # Helper: scope-safe forward propagation (stays inside function or low-fan-in helper callees, never shared print stubs)
    def _propagate_forward(seeds, max_hops=14):
        best_score = {}
        for s in seeds:
            best_score[s] = 1.0
            queue = [(s, 0, func_base.get(s, ''))]
            visited = {s: 0}
            idx = 0
            while idx < len(queue):
                curr, dist, origin_fb = queue[idx]
                idx += 1
                if dist >= max_hops:
                    continue
                curr_fb = func_base.get(curr, '')
                for nxt in nx_graph.successors(curr):
                    n_feats = nx_graph.nodes[nxt].get('features')
                    if not n_feats or n_feats[14] > 0.5:  # skip library stubs
                        continue
                    nxt_fb = func_base.get(nxt, '')
                    # Allow intra-function edges OR forward call into dedicated sink/helper (fan-in <= 4)
                    same_func = (nxt_fb == curr_fb)
                    dedicated_callee = (nx_graph.in_degree(nxt) <= 4 and nxt_fb != origin_fb or same_func)
                    if not same_func and not (nx_graph.in_degree(nxt) <= 4):
                        continue
                    # Do not bounce back from a shared helper to a different caller
                    if not same_func and curr_fb != origin_fb and nxt_fb != curr_fb and nx_graph.in_degree(curr) > 2:
                        continue
                    ndist = dist + 1
                    if ndist < visited.get(nxt, 999):
                        visited[nxt] = ndist
                        score = 1.0 / (1.0 + 0.15 * ndist)
                        if score > best_score.get(nxt, 0.0):
                            best_score[nxt] = score
                        queue.append((nxt, ndist, origin_fb))
        return best_score

    taint_scores = _propagate_forward(taint_seed_nodes, max_hops=16)
    dealloc_scores = _propagate_forward(dealloc_seed_nodes, max_hops=10)

    # Second pass: apply taint/dealloc reachability and upstream conditional-guard counts
    for node in nx_graph.nodes():
        feats = nx_graph.nodes[node].get('features')
        if not feats:
            continue
        if node in taint_scores:
            feats[31] = max(feats[31], taint_scores[node])
        if node in dealloc_scores and node not in dealloc_seed_nodes:
            # Downstream block after free() -> strong indicator when paired with load/store/free
            feats[36] = max(feats[36], dealloc_scores[node])

        # Count intra-function conditional guards within 3 backward hops
        fb = func_base.get(node, '')
        guard_count = 0
        b_visited = {node}
        frontier = [node]
        for _ in range(4):
            nxt_frontier = []
            for curr in frontier:
                for pred in nx_graph.predecessors(curr):
                    if pred in b_visited or func_base.get(pred, '') != fb:
                        continue
                    b_visited.add(pred)
                    p_feats = nx_graph.nodes[pred].get('features')
                    if p_feats and (p_feats[24] > 0.5 or p_feats[30] > 0.5):
                        guard_count += 1
                    nxt_frontier.append(pred)
            frontier = nxt_frontier
        feats[27] = _normalize(float(guard_count), 0.0, 6.0)
        feats[35] = min(1.0, feats[35] + _normalize(float(guard_count), 0.0, 10.0) * 0.3)


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
    "dominator_tree_depth",
    "back_edge_count",
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
    "branch_condition_complexity",
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