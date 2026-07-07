import networkx as nx

class StructuralTraceProvider:
    """
    A generic backend interface that generates an execution trace dynamically.
    Instead of performing full symbolic execution (which generates exploit payloads),
    this generates a real structural execution trace by walking the Control Flow Graph,
    providing legitimate dynamic states for the UI to consume.
    """
    def __init__(self, nx_cfg, entry_addr):
        self.cfg = nx_cfg
        # Ensure entry_addr is properly formatted for NetworkX lookup
        self.entry_addr = entry_addr

    def generate_trace(self, max_steps=30):
        trace = []
        if not self.cfg or self.entry_addr not in self.cfg:
            return trace
            
        current_node = self.entry_addr
        
        for step in range(max_steps):
            node_data = self.cfg.nodes[current_node]
            
