import angr
import claripy
import time
from typing import Dict, List, Any, Optional, Tuple

# Taint analysis — source injection and sink detection
from core.taint_engine import (
    TAINT_SOURCES,
    inject_taint,
    check_sink,
    TaintSinkHit,
    is_tainted,
)

def instrument_state(state):
    """
    Registers memory and simprocedure breakpoints on the state to trace allocations
    and verify safety properties.

    Also registers a syscall breakpoint as a taint-injection fallback for statically
    linked or LTO-compiled binaries where read/recv are inlined and never appear as
    angr SimProcedures. The syscall hook fires on the raw sys_read (x86-64: 0,
    ARM64: 63) and injects symbolic taint bytes directly into the destination buffer,
    ensuring taint propagation works regardless of linking model.
    """
    state.inspect.b('mem_read',      when=angr.BP_BEFORE, action=track_mem_read)
    state.inspect.b('mem_write',     when=angr.BP_BEFORE, action=track_mem_write)
    state.inspect.b('simprocedure',  when=angr.BP_BEFORE, action=track_simproc_before)
    state.inspect.b('simprocedure',  when=angr.BP_AFTER,  action=track_simproc_after)
    state.inspect.b('syscall',       when=angr.BP_AFTER,  action=_track_syscall_taint)
    state.vuln_tracker.log("State instrumented with safety breakpoints (including syscall taint fallback).")

# ── Syscall numbers for sys_read ─────────────────────────────────────────────
# x86-64: 0, x86-32: 3, ARM/THUMB: 3, AArch64: 63, MIPS: 4003
_SYS_READ_NUMBERS = {0, 3, 63, 4003}

def _track_syscall_taint(state):
    """
    Syscall-level taint injection fallback.

    Fires when angr simulates a syscall AFTER it completes. If the syscall number
    is sys_read (see _SYS_READ_NUMBERS), injects symbolic taint bytes into the
    destination buffer. This handles binaries that inline read() rather than calling
    it through the PLT (static linking, LTO, musl libc, etc.).

    Calling convention for sys_read:
      x86-64 / ARM64: rax/x8 = syscall_nr, rdi/x0 = fd, rsi/x1 = buf, rdx/x2 = count
      x86-32 / ARM:   eax/r7 = syscall_nr, ebx/r0 = fd, ecx/r1 = buf, edx/r2 = count
      MIPS:           v0 = syscall_nr, a0 = fd, a1 = buf, a2 = count
    """
    try:
        tracker = getattr(state, 'vuln_tracker', None)
        if tracker is None:
            return

        arch = state.arch.name
        # Retrieve syscall number and arguments based on architecture
        if 'AMD64' in arch or 'AARCH64' in arch:
            syscall_nr_reg = 'rax' if 'AMD64' in arch else 'x8'
            buf_reg        = 'rsi' if 'AMD64' in arch else 'x1'
            len_reg        = 'rdx' if 'AMD64' in arch else 'x2'
        elif 'ARM' in arch:
            syscall_nr_reg, buf_reg, len_reg = 'r7', 'r1', 'r2'
        elif 'X86' in arch:
            syscall_nr_reg, buf_reg, len_reg = 'eax', 'ecx', 'edx'
        elif 'MIPS' in arch:
            syscall_nr_reg, buf_reg, len_reg = 'v0', 'a1', 'a2'
        else:
            return

        syscall_nr = state.solver.eval(getattr(state.regs, syscall_nr_reg, 0))
        if syscall_nr not in _SYS_READ_NUMBERS:
            return

        buf_ptr   = getattr(state.regs, buf_reg, None)
        raw_count = getattr(state.regs, len_reg, None)
        if buf_ptr is None or raw_count is None:
            return

        try:
            count = state.solver.eval(raw_count)
        except Exception:
            count = 128  # conservative fallback

        if count <= 0 or count > 4096:
            count = 128

        site = state.addr
        inject_taint(state, 'sys_read', site, buf_ptr, int(count))
        tracker.log(
            f"[TAINT/SYSCALL] sys_read at {hex(site)}: injected {count} taint bytes into buf={buf_ptr}"
        )
    except Exception:
        pass  # Never crash the analysis engine on a taint hook failure



def track_mem_read(state):
    addr = state.inspect.mem_read_address
    length = state.inspect.mem_read_length
    verify_memory_safety(state, addr, length, is_write=False)

def track_mem_write(state):
    addr = state.inspect.mem_write_address
    length = state.inspect.mem_write_length
    verify_memory_safety(state, addr, length, is_write=True)

def get_argument_value(state, index):
    arch = state.arch.name
    if 'AMD64' in arch:
        regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        if index < len(regs):
            return getattr(state.regs, regs[index])
    elif 'AARCH64' in arch:
        regs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
        if index < len(regs):
            return getattr(state.regs, regs[index])
    elif 'ARM' in arch:
        regs = ['r0', 'r1', 'r2', 'r3']
        if index < len(regs):
            return getattr(state.regs, regs[index])
    elif 'MIPS' in arch:
        regs = ['a0', 'a1', 'a2', 'a3']
        if index < len(regs):
            return getattr(state.regs, regs[index])
    elif 'X86' in arch:
        sp = state.regs.esp
        addr = sp + 4 + index * 4
        return state.memory.load(addr, 4, endness=state.arch.memory_endness)
    
    try:
        cc = state.project.factory.cc()
        import angr.sim_type
        arg_tys = [angr.sim_type.SimTypeInt()] * (index + 1)
        proto = angr.sim_type.SimTypeFunction(arg_tys, angr.sim_type.SimTypeInt()).with_arch(state.arch)
        args = cc.get_args(state, proto)
        return args[index]
    except Exception:
        pass
        
    return None

def track_simproc_before(state):
    name = state.inspect.simprocedure_name
    if name is None:
        return
        
    clean_name = name.strip('_')
    tracker = state.vuln_tracker
    site = state.inspect.simprocedure_addr

    # ── Taint Sink Check ─────────────────────────────────────────────────────
    # Collect arguments and check if any tainted value reaches a dangerous sink
    _SINK_MAX_ARGS = 4
    args = []
    for i in range(_SINK_MAX_ARGS):
        try:
            args.append(get_argument_value(state, i))
        except Exception:
            args.append(None)

    sink_hit: Optional[TaintSinkHit] = check_sink(state, clean_name, site, args)
    if sink_hit is not None:
        is_exploit = True
        details = sink_hit.details
        vuln_type = f"TAINT_{sink_hit.sink_category}"
        
        # For copy sinks (strcpy, memcpy, etc.), check if they actually overflow!
        if clean_name in ("strcpy", "strcat", "strncpy", "memcpy", "memmove"):
            dest_ptr = args[0]
            src_ptr = args[1]
            n_arg = args[2] if clean_name in ("strncpy", "memcpy", "memmove") else None
            
            is_overflow, overflow_details, dest_size = check_copy_overflow(state, clean_name, dest_ptr, src_ptr, n_arg)
            if not is_overflow:
                is_exploit = False
            else:
                details = overflow_details
                origin = get_pointer_origin(state, dest_ptr)
                if origin == 'stack':
                    vuln_type = "STACK_OVERFLOW"
                else:
                    vuln_type = "OOB_WRITE"
                    
        if is_exploit:
            report_finding(
                state,
                vuln_type,
                details,
                site,
            )
            tracker.log(f"[EXPLOIT-SINK] {vuln_type} proved at {hex(site)} via '{clean_name}'")

    # ── Memory allocation tracking ────────────────────────────────────────────
    if clean_name == 'malloc':
        try:
            size = get_argument_value(state, 0)
            tracker.pending_malloc_size = size
            tracker.log(f"Intercepted malloc call before. size={size}")
            verify_allocation_size(state, size)
        except Exception as e:
            tracker.log(f"Failed to parse malloc arg: {e}")
            
    elif clean_name == 'calloc':
        try:
            nmemb = get_argument_value(state, 0)
            size = get_argument_value(state, 1)
            tracker.pending_calloc_num = nmemb
            tracker.pending_calloc_size = size
            tracker.log(f"Intercepted calloc call before. nmemb={nmemb}, size={size}")
            verify_allocation_size(state, nmemb * size)
        except Exception as e:
            tracker.log(f"Failed to parse calloc arg: {e}")
            
    elif clean_name == 'realloc':
        try:
            ptr = get_argument_value(state, 0)
            size = get_argument_value(state, 1)
            tracker.pending_realloc_ptr = ptr
            tracker.pending_realloc_size = size
            tracker.log(f"Intercepted realloc call before. ptr={ptr}, size={size}")
            verify_free_pointer(state, ptr, is_realloc=True)
            verify_allocation_size(state, size)
        except Exception as e:
            tracker.log(f"Failed to parse realloc arg: {e}")
            
    elif clean_name == 'free':
        try:
            ptr = get_argument_value(state, 0)
            tracker.log(f"Intercepted free call before. ptr={ptr}")
            verify_free_pointer(state, ptr)
        except Exception as e:
            tracker.log(f"Failed to parse free arg: {e}")

def track_simproc_after(state):
    name = state.inspect.simprocedure_name
    if name is None:
        return
        
    clean_name = name.strip('_')
    tracker = state.vuln_tracker
    site = state.inspect.simprocedure_addr
    ret_val = state.inspect.simprocedure_result
    
    if ret_val is None:
        return

    # ── Taint Source Injection ────────────────────────────────────────────────
    # When an I/O function returns, inject symbolic taint markers into the output buffer.
    if clean_name in TAINT_SOURCES:
        buf_arg_idx, len_arg_idx = TAINT_SOURCES[clean_name]
        try:
            if buf_arg_idx is not None:
                buf_ptr = get_argument_value(state, buf_arg_idx)
                if len_arg_idx is not None:
                    raw_len = get_argument_value(state, len_arg_idx)
                    try:
                        length = state.solver.eval(raw_len)
                    except Exception:
                        length = 128  # conservative fallback
                else:
                    # gets() / getenv() — use a conservative bound
                    length = 256
                if buf_ptr is not None and length > 0:
                    inject_taint(state, clean_name, site, buf_ptr, int(length))
            else:
                # Variadic sources (scanf) or return-value sources (getenv)
                # Mark the return value itself as tainted by writing to a known sym var
                var_name = f"taint_{clean_name}_{hex(site)}_retval"
                taint_sym = claripy.BVS(var_name, ret_val.size() if hasattr(ret_val, 'size') else 64)
                if isinstance(tracker.taint_set, set):
                    tracker.taint_set.add(var_name)
                    if not hasattr(tracker, 'taint_sources'):
                        tracker.taint_sources = []
                tracker.log(f"[TAINT] Return-value taint marker for '{clean_name}' at {hex(site)}")
        except Exception as e:
            tracker.log(f"[TAINT] Source injection error for '{clean_name}': {e}")

    # ── Heap allocation tracking ──────────────────────────────────────────────
    if clean_name == 'malloc' and tracker.pending_malloc_size is not None:
        size = tracker.pending_malloc_size
        tracker.pending_malloc_size = None
        alloc_id = f"heap_{hex(site)}_{len(tracker.allocations) + len(tracker.freed_allocations)}"
        tracker.add_allocation(alloc_id, ret_val, size, 'heap', site)
        
    elif clean_name == 'calloc' and tracker.pending_calloc_num is not None:
        nmemb = tracker.pending_calloc_num
        size = tracker.pending_calloc_size
        tracker.pending_calloc_num = None
        tracker.pending_calloc_size = None
        alloc_id = f"heap_{hex(site)}_{len(tracker.allocations) + len(tracker.freed_allocations)}"
        tracker.add_allocation(alloc_id, ret_val, nmemb * size, 'heap', site)
        
    elif clean_name == 'realloc' and tracker.pending_realloc_ptr is not None:
        old_ptr = tracker.pending_realloc_ptr
        size = tracker.pending_realloc_size
        tracker.pending_realloc_ptr = None
        tracker.pending_realloc_size = None
        
        # Free old allocation
        matched_id = None
        for alloc_id, obj in list(tracker.allocations.items()):
            if state.solver.is_true(old_ptr == obj.start_addr):
                matched_id = alloc_id
                break
        if matched_id is not None:
            tracker.free_allocation(matched_id, site)
            
        alloc_id = f"heap_{hex(site)}_{len(tracker.allocations) + len(tracker.freed_allocations)}"
        tracker.add_allocation(alloc_id, ret_val, size, 'heap', site)

def get_precise_site(state) -> int:
    try:
        loader = state.project.loader
        obj = loader.find_object_containing(state.addr)
        if obj is not None and obj == loader.extern_object:
            site = state.callstack.call_site_addr
            if site is not None and site != 0:
                return site
            ret_addr = state.callstack.ret_addr
            if ret_addr is not None and ret_addr != 0:
                return ret_addr - 4
            
            # Fallback to CPU registers
            arch = state.arch.name
            if 'ARM' in arch or 'AARCH64' in arch:
                if hasattr(state.regs, 'lr'):
                    lr = state.solver.eval(state.regs.lr)
