import React, { useState } from 'react';
import { Copy, Check, Terminal } from 'lucide-react';

const overflowLogs = [
  { type: 'LOAD', text: '[LOADER] Mach-O AArch64: cwe120_buffer_overflow.bin (33.2 KB)' },
  { type: 'CFG', text: '[CFG] Recovered 31 basic blocks, 42 edges, 4 subroutines via VEX IR' },
  { type: 'GNN', text: '[SAGE-CONV] Evaluated embeddings; block 0x10000051c risk: 0.942 (Critical)' },
  { type: 'SYM', text: '[ANGR] Directed symbolic slice initialized; stdin = claripy.BVS(320 bits)' },
  { type: 'PROP', text: '[INVARIANT] strncpy_chk @ 0x10000051c; dest_size=8, copy_len=32' },
  { type: 'Z3', text: '[Z3] Assert path predicates: (bvugt copy_len (_ bv8 64))' },
  { type: 'SAT', text: '[Z3] SATISFIABLE in 3.1ms. Counterexample synthesized.' },
  { type: 'REPRO', text: '[EXPLOIT] Synthesized 40 bytes: [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, …]' },
  { type: 'SUCCESS', text: '[VERIFIED] STACK_OVERFLOW proved. CVSS 7.9 HIGH. Zero false positives.' },
];

const secureLogs = [
  { type: 'LOAD', text: '[LOADER] Mach-O AArch64: secure_program.bin (33.3 KB)' },
  { type: 'CFG', text: '[CFG] Recovered 31 basic blocks, 42 edges, 2 subroutines' },
  { type: 'GNN', text: '[SAGE-CONV] Top block risk: 0.14 (Benign) — 99.6% paths pruned' },
  { type: 'SYM', text: '[ANGR] 13 symbolic states checked against memory invariants' },
  { type: 'Z3', text: '[Z3] Evaluating memory-safety invariants vs branch conditions' },
  { type: 'SAT', text: '[Z3] UNSATISFIABLE — boundary invariants hold on all execution paths' },
  { type: 'SUCCESS', text: '[CLEAN] Zero vulnerabilities proved. Formal safety verified.' },
];

function logColor(type: string) {
  switch (type) {
    case 'GNN':
      return 'text-emerald-400';
    case 'PROP':
      return 'text-rose-400';
    case 'SAT':
      return 'text-emerald-300 font-semibold';
    case 'SUCCESS':
      return 'text-emerald-400 font-semibold';
    case 'CFG':
      return 'text-indigo-400';
    case 'Z3':
      return 'text-cyan-400';
    default:
      return 'text-zinc-300';
  }
}

export const InteractiveTerminal: React.FC = () => {
  const [selectedTarget, setSelectedTarget] = useState<'overflow' | 'secure'>('overflow');
  const [copied, setCopied] = useState(false);
  const logs = selectedTarget === 'overflow' ? overflowLogs : secureLogs;

  const handleCopy = () => {
    navigator.clipboard.writeText(logs.map((l) => l.text).join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section id="telemetry" className="relative px-4 py-16 sm:px-6 lg:px-8 border-t border-border">
      <div className="mx-auto max-w-7xl">
        <div className="grid grid-cols-1 items-start gap-8 lg:grid-cols-12">
          <div className="space-y-3 lg:col-span-4">
            <div className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-rose-500 font-semibold">
              <Terminal className="h-3.5 w-3.5" />
              <span>Engine Stream</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-primary sm:text-3xl">
              Live Solver Telemetry
            </h2>
            <p className="text-sm text-secondary leading-relaxed">
              Real execution trace showing the engine progression: from VEX IR disassembly and GraphSAGE inference to Z3 SMT constraint solving.
            </p>
          </div>

          <div className="lg:col-span-8 rounded-xl border border-border bg-surface shadow-2xl overflow-hidden">
            {/* Minimal terminal topbar */}
            <div className="flex items-center justify-between border-b border-border px-4 py-3 bg-surface-raised/60">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-rose-500/80" />
                <span className="h-2.5 w-2.5 rounded-full bg-amber-500/80" />
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-500/80" />
                <span className="ml-2 font-mono text-xs text-secondary">vanta_cli — telemetry</span>
              </div>

              <div className="flex items-center gap-2">
                <div className="flex rounded-md border border-border bg-surface p-0.5 text-[11px] font-mono">
                  <button
                    type="button"
                    onClick={() => setSelectedTarget('overflow')}
                    className={`rounded px-2.5 py-1 transition-colors ${
                      selectedTarget === 'overflow'
                        ? 'bg-surface-raised text-rose-400 font-semibold border border-border'
                        : 'text-secondary hover:text-primary'
                    }`}
                  >
                    Vulnerable Trace
                  </button>
                  <button
                    type="button"
                    onClick={() => setSelectedTarget('secure')}
                    className={`rounded px-2.5 py-1 transition-colors ${
                      selectedTarget === 'secure'
                        ? 'bg-surface-raised text-emerald-400 font-semibold border border-border'
                        : 'text-secondary hover:text-primary'
                    }`}
                  >
                    Guarded Trace
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleCopy}
                  className="rounded p-1.5 text-zinc-500 hover:text-zinc-200 transition-colors"
                  aria-label="Copy logs"
                >
                  {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                </button>
              </div>
            </div>

            {/* Terminal Body */}
            <div className="p-4 font-mono text-xs leading-relaxed space-y-1.5 overflow-x-auto min-h-[240px]">
              {logs.map((line, idx) => (
                <div key={idx} className="flex items-start gap-3">
                  <span className="select-none text-zinc-600 w-5 text-right font-mono text-[11px]">
                    {String(idx + 1).padStart(2, '0')}
                  </span>
                  <span className={logColor(line.type)}>{line.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
