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
        n = name.lower().lstrip('_')

        def _with_name(proc, sym_name: str):
            if proc is not None:
                try:
                    proc.display_name = sym_name
                except Exception:
                    pass
            return proc

        if n in ('strcpy_chk', 'strcpy'):
            return _with_name(angr.SIM_PROCEDURES['libc']['strcpy'](), n)
        if n in ('strncpy_chk', 'strncpy'):
            return _with_name(angr.SIM_PROCEDURES['libc']['strncpy'](), n)
        if n in ('strcat_chk', 'strcat'):
            if 'strcat' in angr.SIM_PROCEDURES['libc']:
                return _with_name(angr.SIM_PROCEDURES['libc']['strcat'](), n)
            return _with_name(angr.SIM_PROCEDURES['libc']['strcpy'](), n)
        if n in ('memcpy_chk', 'memcpy', 'memmove_chk', 'memmove', 'bcopy'):
            return _with_name(angr.SIM_PROCEDURES['libc']['memcpy'](), n)
        if n in ('memset_chk', 'memset'):
            return _with_name(angr.SIM_PROCEDURES['libc']['memset'](), n)
        if n in ('snprintf_chk', 'snprintf', 'vsnprintf_chk', 'vsnprintf', 'sprintf_chk', 'sprintf', 'vsprintf'):
            is_bounded = 'snprintf' in n

            class TaintPropagatingPrintfBuf(angr.SimProcedure):
                def run(self, dst_ptr, arg1=None, arg2=None, arg3=None, arg4=None, arg5=None):
                    try:
                        from core.taint_engine import is_tainted
                        st = self.state
                        tracker = getattr(st, 'vuln_tracker', None)
                        taint_set = getattr(tracker, 'taint_set', set()) if tracker else set()

                        max_copy = 64
                        if is_bounded and arg1 is not None:
                            try:
                                if not getattr(arg1, 'symbolic', False):
                                    max_copy = max(1, min(int(st.solver.eval(arg1)), 64))
                            except Exception:
                                max_copy = 64

                        # Gather candidate argument pointers from registers and Apple ARM64 / x86 stack variadic slots
                        candidates = []
                        arch = st.arch.name
                        if 'AARCH64' in arch:
                            reg_names = ['x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
                        elif 'AMD64' in arch:
                            reg_names = ['rsi', 'rdx', 'rcx', 'r8', 'r9']
                        elif 'ARM' in arch:
                            reg_names = ['r1', 'r2', 'r3']
                        else:
                            reg_names = []

                        for rn in reg_names:
                            if hasattr(st.regs, rn):
                                candidates.append(getattr(st.regs, rn))

                        # Apple Silicon (Darwin ARM64) passes variadic arguments (...) on the stack at [sp + 0], [sp + 8], ...
                        try:
                            sp_val = st.regs.sp
                            ptr_bytes = st.arch.bits // 8
                            for slot in range(4):
                                stack_arg = st.memory.load(
                                    sp_val + slot * ptr_bytes,
                                    ptr_bytes,
                                    endness=st.arch.memory_endness,
                                    inspect=False,
                                )
                                candidates.append(stack_arg)
                        except Exception:
                            pass

                        # Check if any candidate pointer dereferences to tainted bytes
                        tainted_src_ptr = None
                        for cand in candidates:
                            if cand is None:
                                continue
                            try:
                                if not getattr(cand, 'symbolic', False):
                                    cand_val = int(st.solver.eval(cand))
                                    # Skip small integers (e.g. maxlen=128, flag=0, objsize=128) and NULL
                                    if cand_val < 0x10000 or cand_val >= (1 << (st.arch.bits - 1)):
                                        continue
                                loaded_probe = st.memory.load(cand, 16, inspect=False)
                                if is_tainted(loaded_probe, taint_set):
                                    tainted_src_ptr = cand
                                    break
                            except Exception:
                                continue

                        if tainted_src_ptr is not None:
                            for i in range(max_copy):
                                try:
                                    b_sym = st.memory.load(tainted_src_ptr + i, 1, inspect=False)
                                    st.memory.store(dst_ptr + i, b_sym, inspect=False)
                                except Exception:
                                    break
                            return max_copy

                        # If a candidate register itself is tainted/symbolic integer, store its bytes
                        for cand in candidates:
                            if cand is not None and (is_tainted(cand, taint_set) or getattr(cand, 'symbolic', False)):
                                try:
                                    st.memory.store(dst_ptr, cand)
                                    return min(max_copy, st.arch.bits // 8)
                                except Exception:
                                    pass

                        st.memory.store(dst_ptr, b'A' * min(max_copy, 32))
                        return min(max_copy, 32)
                    except Exception:
                        return 0

            return _with_name(TaintPropagatingPrintfBuf(display_name=n), n)
        if n in ('read', 'pread', 'recv', 'recvfrom'):
            return _with_name(angr.SIM_PROCEDURES['posix']['read'](display_name=n), n)
        if n in ('fgets', 'gets', 'fread'):
            if n in angr.SIM_PROCEDURES['libc']:
                return _with_name(angr.SIM_PROCEDURES['libc'][n](display_name=n), n)
            return _with_name(angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](display_name=n), n)
        if n in ('printf', 'puts', 'fprintf', 'dprintf', 'vprintf', 'vfprintf'):
            return _with_name(angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](display_name=n, resolves=0), n)
        if n == 'malloc':
            return _with_name(angr.SIM_PROCEDURES['libc']['malloc'](), n)
        if n == 'calloc' and 'calloc' in angr.SIM_PROCEDURES['libc']:
            return _with_name(angr.SIM_PROCEDURES['libc']['calloc'](), n)
        if n == 'realloc' and 'realloc' in angr.SIM_PROCEDURES['libc']:
            return _with_name(angr.SIM_PROCEDURES['libc']['realloc'](), n)
        if n == 'free':
            return _with_name(angr.SIM_PROCEDURES['libc']['free'](), n)
        if n in ('system', 'popen', 'execve', 'execl', 'execlp', 'execvp'):
            if n in angr.SIM_PROCEDURES['libc']:
                return _with_name(angr.SIM_PROCEDURES['libc'][n](display_name=n), n)
            return _with_name(angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained'](display_name=n, resolves=0), n)
        if n == 'exit' or n == '_exit':
            return _with_name(angr.SIM_PROCEDURES['libc']['exit'](), n)
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
