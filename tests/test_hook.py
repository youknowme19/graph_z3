import sys
import os
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("src"))

import angr
from core.interfaces import AnalysisBackendProvider

backend = AnalysisBackendProvider('tests/test_benchmarks_binary', max_steps=150)
proj = backend.engine.project

# Hook symbols
import angr.sim_procedure
class StackChkFailSimProc(angr.SimProcedure):
    def run(self):
        from core.property_engine import report_finding
        details = "Stack canary corruption detected: control flow hijacked or stack buffer overflow occurred."
        site = self.state.addr
        report_finding(self.state, "STACK_OVERFLOW", details, site)
        self.exit(1)

class ReturnUnconstrained(angr.SimProcedure):
    def run(self, *args, **kwargs):
        return self.state.solver.Unconstrained("dummy_ret", self.state.arch.bits)

# Apply hooks
for s in proj.loader.main_object.symbols:
    if s.is_import and s.resolvedby is not None:
        addr = s.resolvedby.rebased_addr
        name = s.name
        clean_name = name
        if clean_name.startswith('_'):
            clean_name = clean_name.lstrip('_')
            
        simproc = None
        if 'stack_chk_fail' in clean_name:
            simproc = StackChkFailSimProc()
        elif 'memcpy_chk' in clean_name:
            simproc = angr.SIM_PROCEDURES['libc']['memcpy']()
        else:
            for lib in ['libc', 'glibc', 'posix']:
                if clean_name in angr.SIM_PROCEDURES[lib]:
                    simproc = angr.SIM_PROCEDURES[lib][clean_name]()
                    break
                    
        if simproc is None and not name.startswith('___stack_chk_guard') and not name.startswith('___stdoutp') and not name.startswith('___stdinp'):
            simproc = ReturnUnconstrained(display_name=clean_name)
            
        if simproc is not None:
            proj.hook(addr, simproc)
            print(f"Hooked {name} at {hex(addr)} with {simproc}")

# Now run scan
vulns = backend.scan_vulnerabilities()
print("\n--- Findings ---")
for v in vulns:
    print(v["vuln_type"], v["vuln_severity"], v["address"], v["vuln_details"])
