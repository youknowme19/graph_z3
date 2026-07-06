import angr
import claripy

class SymbolicEngine:
    """
    An educational wrapper around angr's symbolic execution engine.
    Designed to expose step-by-step path exploration and constraint generation.
    """
    def __init__(self, binary_loader):
        self.project = binary_loader.project
        # Initialize a basic state at the entry point
        self.state = self.project.factory.entry_state()
        
        # Register plugin and instrument
        from core.vuln_plugin import VulnerabilityTrackerPlugin
        from core.property_engine import instrument_state
        self.state.register_plugin('vuln_tracker', VulnerabilityTrackerPlugin())
        instrument_state(self.state)
        
        # Initialize the simulation manager to track execution paths
        self.simgr = self.project.factory.simulation_manager(self.state)
        
        self.execution_trace = []
        self.step_count = 0

    def inject_symbolic_function_args(self, func_addr: int, n_args: int = 4, buf_size_bytes: int = 64):
        """
        Creates a call_state at func_addr and initialises each of the n_args
        argument registers with a fresh symbolic BVS bitvector.  For each
        argument a matching symbolic buffer (allocated in the heap arena) is
        written to memory and the length/size register is constrained by a
        symbolic 'buf_len' variable.  This allows the property engine to detect
        OOB reads/writes and overflow conditions on function parameters even
        when those parameters originate outside the traced entry path.

        The constructed symbolic variables are stored in
        ``state.vuln_tracker.symbolic_variables`` and also returned as a dict.
        """
        import claripy

        arch = self.project.arch.name
        # Argument registers by ABI
        if 'AMD64' in arch:
            arg_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        elif 'AARCH64' in arch:
            arg_regs = ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7']
        elif 'ARM' in arch:
            arg_regs = ['r0', 'r1', 'r2', 'r3']
        elif 'MIPS' in arch:
            arg_regs = ['a0', 'a1', 'a2', 'a3']
        elif 'X86' in arch:
            arg_regs = []  # x86 cdecl: pushed on stack, handled below
        else:
            arg_regs = []

        bits = self.project.arch.bits

        # Start from a blank call_state at the target function
        self.state = self.project.factory.call_state(func_addr)

        from core.vuln_plugin import VulnerabilityTrackerPlugin
        from core.property_engine import instrument_state
        tracker = VulnerabilityTrackerPlugin()

        sym_vars = {}
        # Allocate a slab of symbolic heap memory for pointer args
        heap_base = 0x41000000
        heap_cursor = heap_base

        for i in range(min(n_args, len(arg_regs))):
            reg_name = arg_regs[i]

            # Create symbolic argument value (pointer or integer)
            arg_sym = claripy.BVS(f"arg_{i}", bits)
            sym_vars[f"arg_{i}"] = arg_sym

            # Also create a symbolic buffer that arg_sym points at
            buf_sym = claripy.BVS(f"buf_arg_{i}", buf_size_bytes * 8)
            buf_len_sym = claripy.BVS(f"buf_len_arg_{i}", bits)

            # Constrain buf_len to [1, buf_size_bytes] so OOB checks are meaningful
            self.state.solver.add(buf_len_sym >= 1)
            self.state.solver.add(buf_len_sym <= buf_size_bytes)

            # Write the symbolic buffer into the symbolic heap slab
            self.state.memory.store(heap_cursor, buf_sym)

            # Point arg_sym at the heap slab
            concrete_ptr = claripy.BVV(heap_cursor, bits)
            setattr(self.state.regs, reg_name, concrete_ptr)

            # Register heap allocation so property_engine can bound-check it
            tracker.allocations[f"heap_arg_{i}"] = type(
                'HeapObj', (), {
                    'start_addr': heap_cursor,
                    'size': buf_size_bytes,
                    'origin': 'heap',
                }
            )()

            sym_vars[f"buf_arg_{i}"] = buf_sym
            sym_vars[f"buf_len_arg_{i}"] = buf_len_sym
            tracker.symbolic_variables[f"arg_{i}"] = concrete_ptr
            tracker.symbolic_variables[f"buf_arg_{i}"] = buf_sym
            tracker.symbolic_variables[f"buf_len_arg_{i}"] = buf_len_sym

            heap_cursor += buf_size_bytes + 8  # 8-byte guard gap

        # x86 cdecl: push symbolic args onto the fake stack
        if 'X86' in arch:
            sp = self.state.solver.eval(self.state.regs.esp)
            for i in range(n_args):
                arg_sym = claripy.BVS(f"arg_{i}", 32)
                buf_sym = claripy.BVS(f"buf_arg_{i}", buf_size_bytes * 8)
                buf_len_sym = claripy.BVS(f"buf_len_arg_{i}", 32)
                self.state.solver.add(buf_len_sym >= 1)
                self.state.solver.add(buf_len_sym <= buf_size_bytes)
                self.state.memory.store(heap_cursor, buf_sym)
                ptr = claripy.BVV(heap_cursor, 32)
                self.state.memory.store(sp + 4 + i * 4, ptr, endness=self.project.arch.memory_endness)
                tracker.allocations[f"heap_arg_{i}"] = type(
                    'HeapObj', (), {
                        'start_addr': heap_cursor,
                        'size': buf_size_bytes,
                        'origin': 'heap',
                    }
                )()
                sym_vars[f"arg_{i}"] = ptr
                sym_vars[f"buf_arg_{i}"] = buf_sym
                sym_vars[f"buf_len_arg_{i}"] = buf_len_sym
                tracker.symbolic_variables[f"buf_arg_{i}"] = buf_sym
                tracker.symbolic_variables[f"buf_len_arg_{i}"] = buf_len_sym
                heap_cursor += buf_size_bytes + 8

        self.state.register_plugin('vuln_tracker', tracker)
        instrument_state(self.state)
        self.simgr = self.project.factory.simulation_manager(self.state, save_unsat=True)
        return sym_vars

    def inject_symbolic_input(self, name="stdin_input", size_bytes=32):
        """
        Injects a symbolic variable as standard input using a SimFile wrapper,
        along with symbolic argv[1] and environment variable INPUT.
        """
        sym_var = claripy.BVS(name, size_bytes * 8)
        sim_stdin = angr.SimFile(name="stdin", content=sym_var, size=size_bytes)
        
        # Add symbolic argument argv[1]
        argv1_sym = claripy.BVS("argv1", 64 * 8)
        
        # Add symbolic environment variable
        env_val_sym = claripy.BVS("env_var", 64 * 8)
        
        self.state = self.project.factory.entry_state(
            args=[self.project.filename, argv1_sym],
            env={"INPUT": env_val_sym},
            stdin=sim_stdin
        )
        
        # Register plugin and instrument
        from core.vuln_plugin import VulnerabilityTrackerPlugin
        from core.property_engine import instrument_state
        tracker = VulnerabilityTrackerPlugin()
        tracker.symbolic_variables["stdin_input"] = sym_var
        tracker.symbolic_variables["argv1"] = argv1_sym
        tracker.symbolic_variables["env_var"] = env_val_sym
        
        self.state.register_plugin('vuln_tracker', tracker)
        instrument_state(self.state)
        
        self.simgr = self.project.factory.simulation_manager(self.state, save_unsat=True)
        return sym_var

    def step(self):
        """
        Advances the symbolic execution by one step (typically a basic block)
        and records the path constraints for educational visualization.
        """
        if not self.simgr.active:
            return False

        # Step all active paths forward
        self.simgr.step()
        self.step_count += 1
        
        step_data = {
            'step': self.step_count,
            'active_states': [],
            'deadended_states': len(self.simgr.deadended)
        }

        # Extract educational data from every active path (state)
        for idx, state in enumerate(self.simgr.active):
            addr = state.addr
            
            # Extract the mathematical path constraints generated so far
            constraints = state.solver.constraints
            constraint_strings = [str(c) for c in constraints]
            
            state_info = {
                'state_id': idx,
                'address': hex(addr),
                'constraints': constraint_strings,
                'is_satisfiable': state.solver.satisfiable()
            }
            step_data['active_states'].append(state_info)
            
        self.execution_trace.append(step_data)
        return True

    def explore(self, max_steps=50):
        """
        Explores paths up to a maximum depth to prevent path explosion,
        returning the trace of constraints and states.
        """
        steps = 0
        while self.simgr.active and steps < max_steps:
            self.step()
            steps += 1
            
        return self.execution_trace

    def print_trace(self):
        """
        Utility to print the recorded execution trace to the terminal.
        """
        print(f"--- Symbolic Execution Trace ({self.step_count} steps) ---")
        for step in self.execution_trace:
            print(f"\nStep {step['step']}:")
            print(f"  Active Paths: {len(step['active_states'])}")
            print(f"  Deadended Paths: {step['deadended_states']}")
            for st in step['active_states']:
                print(f"    -> Path {st['state_id']} @ {st['address']}")
                print(f"       Constraints: {st['constraints']}")
                print(f"       Satisfiable: {st['is_satisfiable']}")
