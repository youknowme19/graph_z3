import React, { useState } from 'react';
import { Terminal, Play, RotateCcw, Copy, Check } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const InteractiveTerminal: React.FC = () => {
  const [selectedTarget, setSelectedTarget] = useState<'overflow' | 'secure'>('overflow');
  const [copied, setCopied] = useState(false);

  const overflowLogs = [
    { type: 'INFO', text: '[LOADER] Parsing Mach-O AArch64 binary: cwe120_buffer_overflow.bin (33.2 KB)' },
    { type: 'CFG', text: '[CFG] Recovered 31 basic blocks, 42 control flow edges across 4 subroutines' },
    { type: 'GNN', text: '[SAGE-CONV] Predicting topological risk priors... block 0x10000051c risk: 0.942' },
    { type: 'SYM', text: '[ANGR] Initializing symbolic memory: stdin_payload = claripy.BVS(320 bits)' },
    { type: 'PROP', text: '[SAFETY] Hooked memory sink strncpy_chk @ 0x10000051c; dest_size=8, copy_len=32' },
    { type: 'Z3', text: '[Z3-SMT] Asserting safety predicate violation: copy_len > dest_size' },
    { type: 'SAT', text: '[Z3-SMT] Verdict: SATISFIABLE in 3.1ms. Counterexample synthesized.' },
    { type: 'REPRO', text: '[EXPLOIT] Solved input: [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, ...]' },
    { type: 'SUCCESS', text: '[VERIFIED] STACK_OVERFLOW proved with 100% mathematical certainty. CVSS: 7.9 HIGH' },
  ];

  const secureLogs = [
    { type: 'INFO', text: '[LOADER] Parsing Mach-O AArch64 binary: secure_program.bin (33.3 KB)' },
    { type: 'CFG', text: '[CFG] Recovered 31 basic blocks, 42 control flow edges across 2 subroutines' },
    { type: 'GNN', text: '[SAGE-CONV] Topological risk inference completed; max node risk: 0.14' },
    { type: 'SYM', text: '[ANGR] Exploring execution trace: 13 active symbolic states checked' },
    { type: 'Z3', text: '[Z3-SMT] Querying memory safety invariants against branch conditions' },
    { type: 'SAT', text: '[Z3-SMT] Verdict: UNSATISFIABLE (All safety invariants hold across all paths)' },
    { type: 'SUCCESS', text: '[CLEAN] 0 Vulnerabilities detected. Program is provably secure (Risk: 0.0 / 10)' },
  ];

  const logs = selectedTarget === 'overflow' ? overflowLogs : secureLogs;

  const handleCopy = () => {
    const text = logs.map((l) => l.text).join('\n');
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getLogColor = (type: string) => {
    switch (type) {
      case 'INFO':
        return 'text-slate-400';
      case 'CFG':
        return 'text-cyan-400';
      case 'GNN':
        return 'text-purple-400';
      case 'SYM':
        return 'text-blue-400';
      case 'PROP':
        return 'text-amber-400';
      case 'Z3':
        return 'text-indigo-400';
      case 'SAT':
        return 'text-yellow-300 font-bold';
      case 'REPRO':
        return 'text-emerald-300 font-bold';
      case 'SUCCESS':
        return 'text-emerald-400 font-bold';
      default:
        return 'text-slate-300';
    }
  };

  return (
    <section className="relative py-16 space-y-12">
      <div className="flex justify-center">
        <HoloSticker
          label="LIVE TELEMETRY // CYBER TERMINAL SIMULATOR"
          sublabel="Real-time symbolic trace execution engine"
          variant="cyber"
          rotation={-2}
          floatAnimation="gentle"
          icon={<Terminal className="w-4 h-4 text-cyan-300" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          Under the Hood of the{' '}
          <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
            Reasoning Engine
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Watch how GNN path prioritization, symbolic memory emulation, and the Z3 SMT solver exchange telemetric constraints in real time.
        </p>
      </div>

      {/* Terminal UI Card */}
      <div className="max-w-4xl mx-auto px-4">
        <div className="metamask-card rounded-3xl p-6 sm:p-8 space-y-4 font-mono text-xs">
          {/* Terminal Window Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-red-500/80" />
              <span className="w-3 h-3 rounded-full bg-amber-500/80" />
              <span className="w-3 h-3 rounded-full bg-emerald-500/80" />
              <span className="ml-2 font-bold text-slate-300">
                terminal // graph_z3_cli_session
              </span>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={() => setSelectedTarget('overflow')}
                className={`px-3 py-1 rounded text-xs font-bold transition-all ${
                  selectedTarget === 'overflow'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Buffer Overflow Trace
              </button>
              <button
                onClick={() => setSelectedTarget('secure')}
                className={`px-3 py-1 rounded text-xs font-bold transition-all ${
                  selectedTarget === 'secure'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Secure Program Trace
              </button>
              <button
                onClick={handleCopy}
                className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                title="Copy Terminal Logs"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>

          {/* Terminal Console Output */}
          <div className="p-4 rounded-2xl bg-black border border-slate-900 space-y-2.5 overflow-x-auto min-h-[260px] select-all leading-relaxed">
            {logs.map((line, idx) => (
              <div key={idx} className="flex items-start gap-3">
                <span className="text-slate-600 select-none">{String(idx + 1).padStart(2, '0')}</span>
                <span className={getLogColor(line.type)}>{line.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
};
