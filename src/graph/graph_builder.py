import json
import networkx as nx
from src.graph.feature_extractor import extract_node_features, update_graph_features


class GraphBuilder:
    def __init__(self, binary_loader):
        self.loader = binary_loader
        self.entry_addr = self.loader.project.entry

    # ── Control Flow Graph ────────────────────────────────────────────────────

    def build_networkx_cfg(self):
        angr_cfg = self.loader.get_cfg()
        nx_graph = nx.DiGraph()

        if not angr_cfg:
            return nx_graph

        functions = self.loader.get_functions()
        node_map = {}

        for node in angr_cfg.graph.nodes():
            # Resolve meaningful function name and block offset
            func_name = None
            offset_str = ""
            try:
                func = functions.floor_func(node.addr) if functions else None
                if func:
                    func_name = func.name
                    diff = node.addr - func.addr
                    if diff > 0:
                        offset_str = f"+{hex(diff)}"
            except Exception:
                pass

            if not func_name:
                # Check symbol table
                try:
                    sym = self.loader.project.loader.find_symbol(node.addr)
                    if sym:
                        func_name = sym.name
                except Exception:
                    pass

            if func_name:
                clean_name = f"{func_name}{offset_str}"
                label = f"{clean_name}\n{hex(node.addr)}"
            elif node.name:
                label = f"{node.name}\n{hex(node.addr)}"
                clean_name = node.name
            else:
                clean_name = f"loc_{hex(node.addr)}"
                label = f"{clean_name}\n{hex(node.addr)}"

            instr_count = (
                len(node.instruction_addrs)
                if hasattr(node, 'instruction_addrs') and node.instruction_addrs
                else 0
            )
            is_entry = node.addr == self.entry_addr
            node_class = 'entry' if is_entry else ('syscall' if node.is_syscall else 'internal')

            # Find the section of the binary containing this block
            section_name = ".text"
            try:
                sec = self.loader.project.loader.find_section_containing(node.addr)
                if sec:
                    section_name = sec.name
            except Exception:
                pass

            # Extract disassembly
            disasm_lines = []
            try:
                blk = self.loader.project.factory.block(node.addr)
                if blk and blk.capstone:
                    for insn in blk.capstone.insns:
                        disasm_lines.append(f"{hex(insn.address)}:  {insn.mnemonic:7s} {insn.op_str}")
            except Exception:
                pass

            nx_graph.add_node(
                node.addr,
                label=label,
                name=clean_name,
                addr=hex(node.addr),
                size=getattr(node, 'size', 0),
                type="block",
                instruction_count=instr_count,
                node_class=node_class,
                is_loop_header=False,
                binary_section=section_name,
                disasm=disasm_lines,
            )
            node_map[node.addr] = node

        for src, dst, _ in angr_cfg.graph.edges(data=True):
            if src.addr in nx_graph and dst.addr in nx_graph:
                nx_graph.add_edge(src.addr, dst.addr)

        # Post-process: degree and loop-header detection
        for node in nx_graph.nodes():
            nx_graph.nodes[node]['incoming_edges'] = nx_graph.in_degree(node)
            nx_graph.nodes[node]['outgoing_edges'] = nx_graph.out_degree(node)

        # Detect loop headers via cycles (strongly connected components of size > 1)
        try:
            for scc in nx.strongly_connected_components(nx_graph):
                if len(scc) > 1:
                    entry_node = None
                    for node in scc:
                        if any(pred not in scc for pred in nx_graph.predecessors(node)):
                            entry_node = node
                            break
                    if entry_node is None:
                        entry_node = next(iter(scc))
                    nx_graph.nodes[entry_node]['is_loop_header'] = True
            for node in nx_graph.nodes():
                if nx_graph.has_edge(node, node):
                    nx_graph.nodes[node]['is_loop_header'] = True
        except Exception:
            pass

        # Extract features for all nodes
        for addr, node in node_map.items():
            features = extract_node_features(node, nx_graph, self.loader)
            nx_graph.nodes[addr]['features'] = features

        # Post-process global features (degrees, loop headers, depth)
        update_graph_features(nx_graph, self.entry_addr)

        return nx_graph

    # ── Call Graph ────────────────────────────────────────────────────────────

    def build_networkx_cg(self):
        angr_cg = self.loader.get_call_graph()
        nx_graph = nx.DiGraph()

        if not angr_cg:
            return nx_graph

        functions = self.loader.get_functions()

        # First pass: add all nodes with their metadata
        for node_addr in angr_cg.nodes():
            func = functions.function(node_addr)
            if not func:
                continue

            bb_count = len(func.block_addrs) if hasattr(func, 'block_addrs') else 0
            instr_count = 0
            try:
                for b in func.blocks:
                    if hasattr(b, 'instruction_addrs'):
                        instr_count += len(b.instruction_addrs)
            except Exception:
                pass

            # Cyclomatic complexity
            cyclomatic = 1
            try:
                fg = func.graph
                if fg is not None:
                    n_nodes = fg.number_of_nodes()
                    n_edges = fg.number_of_edges()
                    if n_nodes > 0:
                        cyclomatic = max(1, n_edges - n_nodes + 2)
            except Exception:
                pass

            is_lib = func.is_simprocedure or func.is_plt
            is_entry = func.addr == self.entry_addr or func.name == 'main'

            if is_entry:
                node_class = 'entry'
            elif is_lib:
                node_class = 'library'
            else:
                node_class = 'internal'

            # Binary section
            section_name = ".text"
            try:
                sec = self.loader.project.loader.find_section_containing(func.addr)
                if sec:
                    section_name = sec.name
            except Exception:
                pass

            func_label = func.name if func.name and not func.name.startswith("sub_") else f"{func.name} ({hex(func.addr)})"

            nx_graph.add_node(
                node_addr,
                label=func_label,
                name=func.name,
                addr=hex(func.addr),
                size=getattr(func, 'size', 0),
                type="function",
                basic_block_count=bb_count,
                instruction_count=instr_count,
                cyclomatic_complexity=cyclomatic,
                is_library_call=is_lib,
                is_loop_header=False,
                node_class=node_class,
                binary_section=section_name,
                is_recursive=False,
                callers=[],
                callees=[],
                block_addrs=set(func.block_addrs) if hasattr(func, 'block_addrs') else set(),
            )

        # Add edges
        for src, dst in angr_cg.edges():
            if src in nx_graph and dst in nx_graph:
                nx_graph.add_edge(src, dst)

        # Detect recursive functions (cycles containing the function node or self-loops)
        try:
            for scc in nx.strongly_connected_components(nx_graph):
                if len(scc) > 1:
                    for node in scc:
                        nx_graph.nodes[node]['is_recursive'] = True
            for node in nx_graph.nodes():
                if nx_graph.has_edge(node, node):
                    nx_graph.nodes[node]['is_recursive'] = True
        except Exception:
            pass

        return nx_graph
