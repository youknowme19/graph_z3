import angr
import logging
import networkx as nx

logger = logging.getLogger(__name__)

# Patch cle MachO get_symbol if on macOS to fix list return bug
try:
    from cle.backends.macho.macho import MachO
    _orig_macho_get_symbol = MachO.get_symbol
    def _patched_macho_get_symbol(self, name, *args, **kwargs):
        res = _orig_macho_get_symbol(self, name, *args, **kwargs)
        if isinstance(res, list) and res:
            return res[0]
        return res
    MachO.get_symbol = _patched_macho_get_symbol
except Exception:
    pass


class BinaryLoader:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.project = angr.Project(binary_path, load_options={'auto_load_libs': False})
        self.cfg = None
        self.cg = None

        # Hook standard library procedures if present in symbols or Mach-O stubs
        self._hook_common_procedures()

    def _hook_common_procedures(self):
        """Hooks common libc/POSIX SimProcedures so execution continues through standard wrappers."""
        try:
            # 1. Hook Mach-O __stubs if present
            sec = None
            for s in self.project.loader.main_object.sections:
                if 'stubs' in s.name:
                    sec = s
                    break

            if sec:
                func_import_syms = [
                    sym for sym in self.project.loader.main_object.symbols
                    if getattr(sym, 'is_import', False) and not any(
                        k in sym.name for k in ('_guard', '_ptr', '_val', '_tab', 'stdinp', 'stdoutp', 'stderrp', 'environ', 'errno')
                    )
                ]
                stub_size = 12 if 'AARCH64' in self.project.arch.name else 6
                for idx, sym in enumerate(func_import_syms):
                    stub_addr = sec.vaddr + idx * stub_size
                    clean = sym.name.lstrip('_')
                    proc = self._get_simprocedure_for_name(clean)
                    if proc is not None:
                        try:
                            self.project.hook(stub_addr, proc)
                        except Exception:
                            pass

            # 2. Hook direct symbol table addresses
            for s in self.project.loader.main_object.symbols:
                if not s.name or not s.rebased_addr:
                    continue
                clean = s.name.lstrip('_')
                proc = self._get_simprocedure_for_name(clean)
                if proc is not None:
                    try:
                        self.project.hook(s.rebased_addr, proc)
                    except Exception:
                        pass
        except Exception:
            pass

    def _get_simprocedure_for_name(self, name: str):
        n = name.lower()
        if n in ('strcpy_chk', 'strcpy'):
            return angr.SIM_PROCEDURES['libc']['strcpy']()
        if n in ('strncpy_chk', 'strncpy'):
            return angr.SIM_PROCEDURES['libc']['strncpy']()
        if n in ('memcpy_chk', 'memcpy'):
            return angr.SIM_PROCEDURES['libc']['memcpy']()
        if n in ('memset_chk', 'memset'):
            return angr.SIM_PROCEDURES['libc']['memset']()
        if n in ('snprintf_chk', 'snprintf'):
            class SafeSnprintf(angr.SimProcedure):
                def run(self, dst_ptr, size, fmt_ptr, *args):
                    try:
                        sz = self.state.solver.eval(size) if not getattr(size, 'symbolic', False) else 128
                        self.state.memory.store(dst_ptr, b'A' * min(sz, 64))
                        return min(sz, 64)
                    except Exception:
                        return 0
            return SafeSnprintf()
        if n in ('sprintf_chk', 'sprintf'):
            class SafeSprintf(angr.SimProcedure):
                def run(self, dst_ptr, fmt_ptr, *args):
                    try:
                        self.state.memory.store(dst_ptr, b'A' * 32)
                        return 32
                    except Exception:
                        return 0
            return SafeSprintf()
        if n == 'read':
            return angr.SIM_PROCEDURES['posix']['read']()
        if n in ('printf', 'puts', 'fprintf', 'dprintf', 'vprintf'):
            return angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](resolves=0)
        if n == 'malloc':
            return angr.SIM_PROCEDURES['libc']['malloc']()
        if n == 'free':
            return angr.SIM_PROCEDURES['libc']['free']()
        if n == 'system':
            return angr.SIM_PROCEDURES['libc']['system']()
        if n == 'exit' or n == '_exit':
            return angr.SIM_PROCEDURES['libc']['exit']()
        return None

    def analyze(self):
        logger.info("Analyzing %s ...", self.binary_path)
        # Generate CFG
        self.cfg = self.project.analyses.CFGFast()
        # Call graph is accessible via the knowledge base
        self.cg = self.project.kb.functions.callgraph

        # Map symbol table names into knowledge base functions
        try:
            for s in self.project.loader.main_object.symbols:
                if s.name and s.rebased_addr:
                    clean = s.name.lstrip('_')
                    if clean and not clean.startswith('radr') and '/' not in clean and not clean.endswith('.o') and not clean.endswith('.c') and not clean.startswith('mh_'):
                        if s.rebased_addr in self.project.kb.functions:
                            self.project.kb.functions[s.rebased_addr].name = clean
        except Exception:
            pass

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
