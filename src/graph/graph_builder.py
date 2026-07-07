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

        node_map = {}
        for node in angr_cfg.graph.nodes():
            if node.name:
                label = f"{node.name}\n{hex(node.addr)}"
            else:
                label = f"Block\n{hex(node.addr)}"

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

            nx_graph.add_node(
                node.addr,
                label=label,
                name=node.name if node.name else f"sub_{hex(node.addr)}",
                addr=hex(node.addr),
                size=getattr(node, 'size', 0),
                type="block",
                instruction_count=instr_count,
                node_class=node_class,
                is_loop_header=False,
                binary_section=section_name,
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
