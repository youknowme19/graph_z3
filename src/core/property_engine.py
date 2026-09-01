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

    if clean_name in ("strcpy", "strcat", "strncpy", "memcpy", "memmove"):
        dest_ptr = args[0]
        src_ptr = args[1]
        n_arg = args[2] if clean_name in ("strncpy", "memcpy", "memmove") else None
        
        is_overflow, overflow_details, dest_size = check_copy_overflow(state, clean_name, dest_ptr, src_ptr, n_arg)
        if is_overflow:
            origin = get_pointer_origin(state, dest_ptr)
            vuln_type = "STACK_OVERFLOW" if origin == 'stack' else "OOB_WRITE"
            report_finding(
                state,
                vuln_type,
                overflow_details,
                site,
            )
            tracker.log(f"[EXPLOIT-COPY] {vuln_type} proved at {hex(site)} via '{clean_name}'")
    else:
        sink_hit: Optional[TaintSinkHit] = check_sink(state, clean_name, site, args)
        if sink_hit is not None:
            vuln_type = f"TAINT_{sink_hit.sink_category}"
            report_finding(
                state,
                vuln_type,
                sink_hit.details,
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
                    if lr != 0:
                        return lr - 4
            elif 'AMD64' in arch or 'X86' in arch:
                if hasattr(state.regs, 'rsp'):
                    ret = state.solver.eval(state.memory.load(state.regs.rsp, 8, endness=state.arch.memory_endness))
                    if ret != 0:
                        return ret - 5
    except Exception:
        pass
    return state.addr

def is_unconstrained_parameter(state, addr) -> bool:
    """
    Returns True if addr is a symbolic variable representing an unconstrained function parameter,
    rather than an attacker-controlled input (tainted) or a valid heap/stack pointer.
    """
    if isinstance(addr, int):
        return False
    if not hasattr(addr, 'symbolic') or not addr.symbolic:
        return False
        
    tracker = getattr(state, 'vuln_tracker', None)
    if tracker is not None and is_tainted(addr, tracker.taint_set):
        return False
        
    try:
        sp = state.regs.sp
        if state.solver.max(addr) - state.solver.min(addr) < 0x1000000:
            return False
    except Exception:
        pass

    try:
        # Use 0xf0000000 to be safe for both 32-bit and 64-bit architectures
        if state.solver.max(addr) - state.solver.min(addr) > 0xf0000000:
            return True
    except Exception:
        pass
        
    return False

def get_pointer_origin(state, ptr) -> str:
    """
    Determines if a pointer points to the stack, heap, or global/static memory.
    """
    if is_unconstrained_parameter(state, ptr):
        return 'global'
        
    if is_stack_address(state, ptr):
        return 'stack'
        
    tracker = getattr(state, 'vuln_tracker', None)
    if tracker is not None:
        for alloc_id, obj in tracker.allocations.items():
            cond = (ptr == obj.start_addr)
            if state.solver.satisfiable(extra_constraints=[cond]):
                return 'heap'
        for alloc_id, obj in tracker.freed_allocations.items():
            cond = (ptr == obj.start_addr)
            if state.solver.satisfiable(extra_constraints=[cond]):
                return 'heap'
                
    return 'global'

def find_buffer_size(state, ptr) -> Optional[int]:
    if is_unconstrained_parameter(state, ptr):
        return None
        
    tracker = getattr(state, 'vuln_tracker', None)
    if tracker is not None:
        for alloc_id, obj in tracker.allocations.items():
            cond = (ptr >= obj.start_addr) & (ptr < obj.start_addr + obj.size)
            if state.solver.satisfiable(extra_constraints=[cond]):
                try:
                    offset = state.solver.eval(ptr - obj.start_addr)
                    size_val = state.solver.eval(obj.size)
                    if 0 <= offset < size_val:
                        return size_val - offset
                except Exception:
                    try:
                        return state.solver.eval(obj.size)
                    except Exception:
                        pass
                        
    if is_stack_address(state, ptr):
        try:
            ptr_val = state.solver.eval(ptr)
            arch = state.arch.name
            fp_reg = 'x29' if 'AARCH64' in arch or 'ARM' in arch else ('rbp' if 'AMD64' in arch else 'ebp')
            if hasattr(state.regs, fp_reg):
                fp_val = state.solver.eval(getattr(state.regs, fp_reg))
                if fp_val > ptr_val:
                    return int(fp_val - ptr_val)
            # Fallback to callstack frame
            current_frame = state.callstack.top
            if current_frame is not None and current_frame.stack_ptr is not None:
                sp_val = state.solver.eval(current_frame.stack_ptr)
                if ptr_val > sp_val:
                    return int(ptr_val - sp_val + 64)
        except Exception:
            pass
            
    return None

def check_copy_overflow(state, clean_name, dest_ptr, src_ptr, n_arg=None) -> Tuple[bool, str, Optional[int]]:
    dest_size = find_buffer_size(state, dest_ptr)
    effective_dest_size = dest_size if dest_size is not None else 16
    tracker = getattr(state, 'vuln_tracker', None)
    taint_set = getattr(tracker, 'taint_set', set()) if tracker else set()
    
    if n_arg is not None:
        try:
            if dest_size is not None and state.solver.satisfiable(extra_constraints=[n_arg > dest_size]):
                details = f"Buffer overflow in {clean_name}: size argument {n_arg} can exceed destination buffer size {dest_size}."
                return True, details, dest_size
        except Exception:
            pass
    else:
        try:
            is_src_tainted = is_tainted(src_ptr, taint_set)
            if not is_src_tainted and src_ptr is not None:
                try:
                    loaded = state.memory.load(src_ptr, 8)
                    is_src_tainted = is_tainted(loaded, taint_set)
                except Exception:
                    pass
            if is_src_tainted:
                details = f"Buffer overflow in {clean_name}: tainted source string can exceed destination buffer size {effective_dest_size}."
                return True, details, effective_dest_size

            constraints = []
            for i in range(effective_dest_size + 1):
                char_val = state.memory.load(src_ptr + i, 1)
                constraints.append(char_val != 0)
            if state.solver.satisfiable(extra_constraints=constraints):
                details = f"Buffer overflow in {clean_name}: source string can exceed destination buffer size {effective_dest_size}."
                return True, details, effective_dest_size
        except Exception:
            pass
            
    return False, "", dest_size

def verify_free_pointer(state, ptr, is_realloc=False):
    if state.solver.is_true(ptr == 0):
        return
        
    tracker = state.vuln_tracker
    site = get_precise_site(state)
    
    # 1. Check if matches live allocation
    matched_id = None
    for alloc_id, obj in list(tracker.allocations.items()):
        if state.solver.is_true(ptr == obj.start_addr):
            matched_id = alloc_id
            break
            
    if matched_id is not None:
        tracker.free_allocation(matched_id, site)
        return
        
    # 2. Check if Double Free (matches freed allocation)
    for alloc_id, obj in list(tracker.freed_allocations.items()):
        cond = (ptr == obj.start_addr)
        if state.solver.satisfiable(extra_constraints=[cond]):
            details = (
                f"Double free invariant violated: pointer {ptr} can point to "
                f"freed object {alloc_id} (allocated at {hex(obj.allocation_site)})."
            )
            report_finding(state, "DOUBLE_FREE", details, site, extra_constraints=[cond], relevant_objects=[obj])
            return
            
    # 3. If pointer is not null and cannot match any active allocation, it is an invalid free
    active_conds = [ptr != obj.start_addr for obj in tracker.allocations.values()]
    if state.solver.satisfiable(extra_constraints=active_conds):
        details = f"Invalid free invariant violated: pointer {ptr} does not match any active allocation."
        report_finding(state, "INVALID_FREE", details, site, extra_constraints=active_conds)

def verify_memory_safety(state, addr, size, is_write):
    tracker = state.vuln_tracker
    site = get_precise_site(state)
    
    try:
        size_bytes = state.solver.eval(size)
    except Exception:
        size_bytes = 8  # fallback
        
    if is_unconstrained_parameter(state, addr):
        return
        
    # 1. Null pointer dereference check
    try:
        if not getattr(addr, 'symbolic', False):
            c_val = state.solver.eval(addr)
            if c_val == 0:
                details = f"Null pointer dereference invariant violated: memory address is NULL (0x0)."
                report_finding(state, "NULL_DEREF", details, site, extra_constraints=[addr == 0])
                return
        else:
            # Symbolic address check: must be satisfiable as NULL and not pointing to stack/heap
            if not is_stack_address(state, addr):
                if state.solver.satisfiable(extra_constraints=[addr == 0]):
                    # Ensure it's not a generic filler register by checking if it's tainted or constrained
                    if is_tainted(state, addr) or len(state.solver.constraints) > 0:
                        details = f"Null pointer dereference invariant violated: pointer {addr} can be NULL (0x0)."
                        report_finding(state, "NULL_DEREF", details, site, extra_constraints=[addr == 0])
                        return
    except Exception:
        pass
        
    # 2. Use-after-free check
    for alloc_id, obj in list(tracker.freed_allocations.items()):
        cond = (addr >= obj.start_addr) & (addr < obj.start_addr + obj.size)
        if state.solver.satisfiable(extra_constraints=[cond]):
            if is_stack_address(state, addr) and obj.origin == 'heap':
                continue
            details = (
                f"Use-after-free invariant violated: access at {addr} "
                f"points to freed object {alloc_id} (allocated at {hex(obj.allocation_site)})."
            )
            report_finding(state, "USE_AFTER_FREE", details, site, extra_constraints=[cond], relevant_objects=[obj])
            return

    # 3. Out-of-bounds check against active allocations
    for alloc_id, obj in list(tracker.allocations.items()):
        if is_stack_address(state, addr) and obj.origin == 'heap':
            continue
            
        # Check overflow
        overflow_cond = (addr + size_bytes > obj.start_addr + obj.size)
        base_in_bounds = (addr >= obj.start_addr) & (addr < obj.start_addr + obj.size)
        if state.solver.satisfiable(extra_constraints=[base_in_bounds, overflow_cond]):
            if is_tainted(state, addr) or is_write:
                vuln_type = "OOB_WRITE" if is_write else "OOB_READ"
                details = (
                    f"Out-of-bounds boundary invariant violated: access at {addr} "
                    f"can overflow object {alloc_id} (size {obj.size})!"
                )
                report_finding(state, vuln_type, details, site, extra_constraints=[base_in_bounds, overflow_cond], relevant_objects=[obj])
                return
            
        # Check underflow (only for tainted/user-controlled pointers)
        if getattr(addr, 'symbolic', False) and is_tainted(state, addr):
            underflow_neighborhood = (addr >= obj.start_addr - 256) & (addr < obj.start_addr)
            if state.solver.satisfiable(extra_constraints=[underflow_neighborhood]):
                vuln_type = "OOB_WRITE" if is_write else "OOB_READ"
                details = (
                    f"Out-of-bounds boundary invariant violated: access at {addr} "
                    f"can underflow object {alloc_id} (size {obj.size})!"
                )
                report_finding(state, vuln_type, details, site, extra_constraints=[underflow_neighborhood], relevant_objects=[obj])
                return

    # 4. Stack overflow frame-boundary checks
    if is_stack_address(state, addr):
        try:
            current_frame = state.callstack.top
            if current_frame is not None and current_frame.stack_ptr is not None:
                stack_limit = current_frame.stack_ptr
                overflow_cond = (addr + size_bytes > stack_limit)
                is_stack_cond = (addr >= stack_limit - 0x10000) & (addr < stack_limit)
                if state.solver.satisfiable(extra_constraints=[is_stack_cond, overflow_cond]):
                    vuln_type = "STACK_OVERFLOW" if is_write else "OOB_READ"
                    details = (
                        f"Stack buffer safety invariant violated: access at {addr} "
                        f"can overflow stack frame limit {hex(stack_limit)}!"
                    )
                    report_finding(state, vuln_type, details, site, extra_constraints=[is_stack_cond, overflow_cond])
                    return
        except Exception:
            pass

def verify_allocation_size(state, size):
    site = get_precise_site(state)
    try:
        if getattr(size, 'symbolic', False) and is_tainted(state, size):
            bits = size.size()
            max_val = (1 << (bits - 1)) - 1
            overflow_cond = (size > max_val) | (size < 0)
            if state.solver.satisfiable(extra_constraints=[overflow_cond]):
                details = f"Allocation arithmetic safety invariant violated: tainted allocation size {size} can overflow integer boundaries."
                report_finding(state, "INTEGER_OVERFLOW", details, site, extra_constraints=[overflow_cond])
    except Exception:
        pass

def is_stack_address(state, addr):
    try:
        sp = state.regs.sp
        cond = (addr >= sp - 0x100000) & (addr <= sp + 0x100000)
        return state.solver.satisfiable(extra_constraints=[cond])
    except Exception:
        return False

def get_return_value(state):
    arch = state.arch.name
    if 'AMD64' in arch or 'X86' in arch:
        return state.regs.rax
    elif 'ARM' in arch or 'AARCH64' in arch:
        return state.regs.x0 if '64' in arch else state.regs.r0
    elif 'MIPS' in arch:
        return state.regs.v0
    else:
        try:
            return state.regs.ret
        except AttributeError:
            return state.regs.rax

def report_finding(state, vuln_type, details, site, extra_constraints=None, relevant_objects=None):
    tracker = state.vuln_tracker
    
    if extra_constraints:
        tracker.extra_constraints_map[(site, vuln_type)] = list(extra_constraints)
        
    solver_constraints = list(state.solver.constraints)
    if extra_constraints:
        solver_constraints.extend(extra_constraints)
        
    witness_model = {}
    for name, var in tracker.symbolic_variables.items():
        try:
            val = state.solver.eval(var, cast_to=bytes)
            witness_model[name] = val.decode('utf-8', errors='ignore')
        except Exception:
            try:
                val = state.solver.eval(var, cast_to=bytes)
                witness_model[name] = val.hex()
            except Exception:
                pass

    call_stack = []
    try:
        for f in state.callstack:
            call_stack.append(f"{hex(f.call_site_addr)} -> {hex(f.func_addr)}")
    except Exception:
        pass

    registers = {}
    try:
        for reg in ['x0', 'x1', 'x2', 'x3', 'x29', 'x30', 'sp', 'ip', 'rax', 'rbx', 'rcx', 'rdx', 'rsp', 'rbp', 'rip']:
            if hasattr(state.regs, reg):
                val = getattr(state.regs, reg)
                registers[reg] = str(val)
    except Exception:
        pass

    finding = {
        "vuln_type": vuln_type,
        "details": details,
        "instruction_address": site,
        "call_stack": call_stack,
        "witness_model": witness_model,
        "constraints": [str(c) for c in solver_constraints],
        "registers": registers,
        "reasoning_trace": list(tracker.reasoning_trace),
        "relevant_objects": [str(obj) for obj in (relevant_objects or [])],
        "confidence": "HIGH",
        "timestamp": time.time()
    }
    
    if not any(f["instruction_address"] == site and f["vuln_type"] == vuln_type for f in tracker.findings):
        tracker.findings.append(finding)
        tracker.log(f"Safety violation proved: {vuln_type} at {hex(site)}")
