import angr
import logging
import struct
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
        self.stub_symbols = self._parse_macho_stubs()

        # Hook standard library procedures if present in symbols or Mach-O stubs
        self._hook_common_procedures()

    def _parse_macho_stubs(self) -> dict:
        """Resolve Mach-O __stubs virtual addresses to dynamic import symbol names via LC_DYSYMTAB."""
        stubs = {}
        try:
            with open(self.binary_path, "rb") as f:
                buf = f.read()
            if len(buf) < 32:
                return stubs
            magic = struct.unpack_from("<I", buf, 0)[0]
            if magic != 0xFEEDFACF:  # MH_MAGIC_64
                return stubs
            _, _, _, _, ncmds, _, _, _ = struct.unpack_from("<IIIIIIII", buf, 0)
            off = 32
            stubs_sections = []
            symoff = nsyms = stroff = indirectsymoff = nindirectsyms = 0
            for _ in range(ncmds):
                if off + 8 > len(buf):
                    break
                cmd, cmdsize = struct.unpack_from("<II", buf, off)
                if cmdsize == 0:
                    break
                if cmd == 0x19:  # LC_SEGMENT_64
                    nsects = struct.unpack_from("<I", buf, off + 64)[0]
                    soff = off + 72
                    for _ in range(nsects):
                        sectname, _, saddr, ssize, _, _, _, _, _, r1, r2, _ = struct.unpack_from(
                            "<16s16sQQIIIIIIII", buf, soff
                        )
                        sname = sectname.split(b"\x00", 1)[0].decode("latin-1", errors="ignore")
                        if sname in ("__stubs", "__auth_stubs", "__symbol_stub1"):
                            esize = r2 if r2 > 0 else (12 if "AARCH64" in self.project.arch.name else 6)
                            stubs_sections.append((saddr, ssize, r1, esize))
                        soff += 80
                elif cmd == 0x2:  # LC_SYMTAB
                    symoff, nsyms, stroff, _ = struct.unpack_from("<IIII", buf, off + 8)
                elif cmd == 0xB:  # LC_DYSYMTAB
                    vals = struct.unpack_from("<14I", buf, off + 8)
                    indirectsymoff, nindirectsyms = vals[12], vals[13]
                off += cmdsize

            if stubs_sections and symoff and stroff and indirectsymoff:
                for saddr, ssize, r1, esize in stubs_sections:
                    count = ssize // esize
                    for i in range(count):
                        idx_pos = indirectsymoff + (r1 + i) * 4
                        if idx_pos + 4 > len(buf):
                            break
                        sym_idx = struct.unpack_from("<I", buf, idx_pos)[0]
                        if sym_idx >= nsyms or (sym_idx & 0xC0000000):
                            continue
                        nlist_pos = symoff + sym_idx * 16
                        if nlist_pos + 4 > len(buf):
                            continue
                        strx = struct.unpack_from("<I", buf, nlist_pos)[0]
                        end = buf.find(b"\x00", stroff + strx)
                        if end > stroff + strx:
                            raw_name = buf[stroff + strx:end].decode("latin-1", errors="ignore")
                            clean = raw_name.lstrip("_")
                            if clean:
                                stubs[saddr + i * esize] = clean
        except Exception:
            pass
        return stubs

    def _hook_common_procedures(self):
        """Hooks common libc/POSIX SimProcedures so execution continues through standard wrappers."""
        try:
            # 1. Hook exact Mach-O __stubs via LC_DYSYMTAB resolution if available
            if self.stub_symbols:
                for stub_addr, clean in self.stub_symbols.items():
                    proc = self._get_simprocedure_for_name(clean)
                    if proc is not None and not self.project.is_hooked(stub_addr):
                        try:
                            self.project.hook(stub_addr, proc)
                        except Exception:
                            pass
            else:
                # Fallback if LC_DYSYMTAB was unavailable
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
                        if proc is not None and not self.project.is_hooked(stub_addr):
                            try:
                                self.project.hook(stub_addr, proc)
                            except Exception:
                                pass

            # 2. Hook direct symbol table addresses (skip unresolved Mach-O imports pointing to header base)
            min_addr = getattr(self.project.loader.main_object, 'min_addr', 0)
            for s in self.project.loader.main_object.symbols:
                if not s.name or not s.rebased_addr:
                    continue
                if getattr(s, 'is_import', False) and s.rebased_addr == min_addr:
                    continue
                clean = s.name.lstrip('_')
                proc = self._get_simprocedure_for_name(clean)
                if proc is not None and not self.project.is_hooked(s.rebased_addr):
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

        # Map symbol table names and Mach-O indirect stubs into knowledge base functions
        try:
            min_addr = getattr(self.project.loader.main_object, 'min_addr', 0)
            for s in self.project.loader.main_object.symbols:
                if s.name and s.rebased_addr:
                    if getattr(s, 'is_import', False) and s.rebased_addr == min_addr:
                        continue
                    clean = s.name.lstrip('_')
                    if clean and not clean.startswith('radr') and '/' not in clean and not clean.endswith('.o') and not clean.endswith('.c') and not clean.startswith('mh_'):
                        if s.rebased_addr in self.project.kb.functions:
                            self.project.kb.functions[s.rebased_addr].name = clean
            for stub_addr, clean in self.stub_symbols.items():
                if stub_addr in self.project.kb.functions:
                    self.project.kb.functions[stub_addr].name = clean
                    self.project.kb.functions[stub_addr].is_plt = True
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
