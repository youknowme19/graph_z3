import angr
import logging
import networkx as nx

logger = logging.getLogger(__name__)


class BinaryLoader:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        self.cfg = None
        self.cg = None

    def analyze(self):
        logger.info("Analyzing %s ...", self.binary_path)
        # Generate CFG
        self.cfg = self.project.analyses.CFGFast()
        # Call graph is accessible via the knowledge base
        self.cg = self.project.kb.functions.callgraph
        logger.info("Analysis complete for %s", self.binary_path)

    def get_cfg(self):
        return self.cfg

    def get_call_graph(self):
        return self.cg

    def get_functions(self):
        return self.project.kb.functions

    def get_mitigations(self):
        """Extract binary security mitigations (PIE, NX, ASLR, Stack Canary, RELRO)."""
        main_obj = self.project.loader.main_object
        
        is_pie = bool(getattr(main_obj, 'pic', False))
        is_nx = not bool(getattr(main_obj, 'execstack', False))
        is_aslr = bool(getattr(main_obj, 'aslr', True))
        
        has_canary = getattr(main_obj, 'has_canary', None)
        if has_canary is None:
            # Fallback heuristic: check if ___stack_chk_fail or __stack_chk_fail symbol exists
            has_canary = any('stack_chk_fail' in sym.name for sym in main_obj.symbols)

        relro_status = getattr(main_obj, 'relro', None)
        if relro_status is None:
            relro_str = "Partial/Standard"
        elif relro_status == 2:
            relro_str = "Full RELRO"
        elif relro_status == 1:
            relro_str = "Partial RELRO"
        else:
            relro_str = "No RELRO"

        return {
            "pie": is_pie,
            "nx": is_nx,
            "aslr": is_aslr,
            "canary": bool(has_canary),
            "relro": relro_str
        }
