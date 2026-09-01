import React from 'react';
import {
  ArrowRight,
  Cpu,
  Network,
  Binary,
  CheckCircle2,
  XCircle,
  TerminalSquare,
  Zap,
} from 'lucide-react';
import type { SampleBinary } from '../types';

interface LandingPageProps {
  onStartIntake: () => void;
  onSelectSample: (sampleId: string) => void;
  samples: SampleBinary[];
}

export const LandingPage: React.FC<LandingPageProps> = ({
  onStartIntake,
  onSelectSample,
  samples,
}) => {
  return (
    <div className="relative z-10 w-full max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12 space-y-28">
      {/* ── 1. Hero Section with Technical Storytelling ──────────────── */}
      <section className="text-center pt-8 pb-12 space-y-8">
        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-mono tracking-wider uppercase">
          <Zap className="w-3.5 h-3.5 animate-pulse" />
          <span>Neuro-Symbolic Hybrid Architecture</span>
        </div>

        <h1 className="text-4xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight text-slate-100 max-w-5xl mx-auto leading-[1.1]">
          Where <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">Graph Neural Networks</span> meet <span className="bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">Formal SMT Verification</span>
        </h1>

        <p className="text-base sm:text-lg text-slate-400 max-w-3xl mx-auto leading-relaxed font-sans">
          Traditional binary fuzzers suffer from exponential path explosion, while static analyzers drown teams in false positives. <strong className="text-slate-200 font-semibold">GRAPH_Z3</strong> uses GNN pre-filtering to predict vulnerable control-flow subgraphs, guiding the <strong className="text-slate-200 font-semibold">angr</strong> symbolic engine and <strong className="text-slate-200 font-semibold">Z3 SMT solver</strong> to generate verified exploit primitives with zero false positives.
        </p>

        {/* Hero CTAs */}
        <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
          <button
            onClick={onStartIntake}
            className="group flex items-center gap-2.5 px-6 py-3.5 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm tracking-wide transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 hover:scale-[1.02]"
          >
            <span>Analyze Binary Target</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1 transition-transform" />
          </button>

          <button
            onClick={() => onSelectSample('cwe120_buffer_overflow')}
            className="flex items-center gap-2 px-5 py-3.5 rounded-xl bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-slate-100 border border-slate-700 text-sm font-semibold transition-all"
          >
            <TerminalSquare className="w-4 h-4 text-cyan-400" />
            <span>Launch Buffer Overflow Demo</span>
          </button>
        </div>

        {/* Live Architecture Micro-Telemetry Badges */}
        <div className="pt-8 grid grid-cols-2 md:grid-cols-4 gap-3 max-w-4xl mx-auto font-mono text-xs">
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
            <span className="text-slate-400">ML Pre-Filter</span>
            <span className="text-cyan-400 font-bold mt-1">40-Dim SageConv GNN</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
            <span className="text-slate-400">Symbolic Engine</span>
            <span className="text-blue-400 font-bold mt-1">angr SimProcedures</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
            <span className="text-slate-400">Theorem Prover</span>
            <span className="text-purple-400 font-bold mt-1">Z3 SMT (SAT / UNSAT)</span>
          </div>
          <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 flex flex-col items-center">
            <span className="text-slate-400">Exploit Verification</span>
            <span className="text-emerald-400 font-bold mt-1">CVSS v3.1 + SARIF</span>
          </div>
        </div>
      </section>

      {/* ── 2. Storytelling: The 3-Stage Pipeline ─────────────────── */}
      <section className="space-y-12">
        <div className="text-center space-y-3">
          <h2 className="text-2xl sm:text-3xl font-bold text-slate-100">
            The Neuro-Symbolic Verification Pipeline
          </h2>
          <p className="text-sm text-slate-400 max-w-2xl mx-auto">
            How graph neural embeddings and formal methods collaborate to solve complex binary security challenges.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Step 1 */}
          <div className="relative p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/40 transition-all group flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-cyan-400 font-bold">PHASE 01</span>
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                  <Network className="w-5 h-5" />
                </div>
              </div>
              <h3 className="text-lg font-bold text-slate-100">
                GNN Attack Surface Pruning
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Extracts interprocedural Control Flow Graphs (CFG) and encodes 40 structural features per basic block (cyclomatic complexity, entropy, opcode distribution). GraphSAGE neural layers flag high-risk functions, eliminating 90%+ unexploitable paths.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-slate-800/80 font-mono text-[11px] text-slate-400">
              Mitigates: <span className="text-slate-300">Exponential Path Explosion</span>
            </div>
          </div>

          {/* Step 2 */}
          <div className="relative p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-blue-500/40 transition-all group flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-blue-400 font-bold">PHASE 02</span>
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                  <Cpu className="w-5 h-5" />
                </div>
              </div>
              <h3 className="text-lg font-bold text-slate-100">
                Targeted Symbolic Execution
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                angr injects symbolic bitvectors into user input streams and function parameters. Execution is prioritized along GNN-flagged paths, performing automated loop summarization and detecting memory boundaries.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-slate-800/80 font-mono text-[11px] text-slate-400">
              Framework: <span className="text-slate-300">angr VEX IR Engine</span>
            </div>
          </div>

          {/* Step 3 */}
          <div className="relative p-6 rounded-2xl bg-slate-900/60 border border-slate-800 hover:border-purple-500/40 transition-all group flex flex-col justify-between">
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-purple-400 font-bold">PHASE 03</span>
                <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                  <Binary className="w-5 h-5" />
                </div>
              </div>
              <h3 className="text-lg font-bold text-slate-100">
                Z3 SMT Exploit Proofs
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                When a security sink or instruction pointer hijack is reached, Z3 proves constraint satisfiability (SAT) and extracts concrete payload bytes. The Exploitability Engine classifies primitives (RET2TEXT, ROP, UAF) with CVSS v3.1 gradient scoring.
              </p>
            </div>
            <div className="mt-6 pt-4 border-t border-slate-800/80 font-mono text-[11px] text-slate-400">
              Output: <span className="text-slate-300">Deterministic Exploit Payload</span>
            </div>
          </div>
        </div>
      </section>

      {/* ── 3. Comparative Benchmarks Table ───────────────────────── */}
      <section className="space-y-6">
        <div className="text-center space-y-2">
          <h2 className="text-xl sm:text-2xl font-bold text-slate-100">
            How GRAPH_Z3 Compares to Traditional Approaches
          </h2>
          <p className="text-xs sm:text-sm text-slate-400">
            Evaluating false positive rates, constraint completeness, and exploit verification.
          </p>
        </div>

        <div className="overflow-x-auto rounded-2xl border border-slate-800 bg-slate-900/40">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/60 text-slate-400 font-mono uppercase tracking-wider">
                <th className="p-4">Capability</th>
                <th className="p-4">Fuzzers (AFL/LibFuzzer)</th>
                <th className="p-4">Static Analyzers</th>
                <th className="p-4">Pure Symbolic (KLEE)</th>
                <th className="p-4 text-cyan-400 bg-cyan-950/30">GRAPH_Z3 (Hybrid)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans">
              <tr>
                <td className="p-4 font-semibold text-slate-200">Zero False Positive Rate</td>
                <td className="p-4 text-emerald-400 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4" /> Yes (Crash based)</td>
                <td className="p-4 text-red-400"><span className="flex items-center gap-1.5"><XCircle className="w-4 h-4" /> No (30-80% noise)</span></td>
                <td className="p-4 text-emerald-400 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4" /> Yes (SMT Proof)</td>
                <td className="p-4 text-cyan-300 font-bold bg-cyan-950/20 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-cyan-400" /> Yes (Z3 SMT Proof)</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-slate-200">Path Explosion Resistance</td>
                <td className="p-4 text-yellow-400">Moderate (Random/Branch)</td>
                <td className="p-4 text-emerald-400 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4" /> High (AST heuristics)</td>
                <td className="p-4 text-red-400 flex items-center gap-1.5"><XCircle className="w-4 h-4" /> Poor (Exhausts RAM)</td>
                <td className="p-4 text-cyan-300 font-bold bg-cyan-950/20 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-cyan-400" /> High (GNN Pre-Filter)</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-slate-200">Exploit Primitive Extraction</td>
                <td className="p-4 text-red-400 flex items-center gap-1.5"><XCircle className="w-4 h-4" /> None (Raw crash only)</td>
                <td className="p-4 text-red-400 flex items-center gap-1.5"><XCircle className="w-4 h-4" /> None (Pattern only)</td>
                <td className="p-4 text-yellow-400">Manual constraint analysis</td>
                <td className="p-4 text-cyan-300 font-bold bg-cyan-950/20 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-cyan-400" /> Automated (RET2TEXT/ROP/UAF)</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-slate-200">CVSS v3.1 Vector Estimation</td>
                <td className="p-4 text-slate-400">Manual</td>
                <td className="p-4 text-slate-400">Static rule table</td>
                <td className="p-4 text-slate-400">None</td>
                <td className="p-4 text-cyan-300 font-bold bg-cyan-950/20 flex items-center gap-1.5"><CheckCircle2 className="w-4 h-4 text-cyan-400" /> Dynamic Gradient Model</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* ── 4. Quick Demo Binary Selector ──────────────────────────── */}
      <section className="space-y-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-100">
              Interactive Test Binaries
            </h2>
            <p className="text-xs sm:text-sm text-slate-400">
              Launch one-click verification on standard CWE benchmark binaries.
            </p>
          </div>
          <button
            onClick={onStartIntake}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
          >
            <span>Or upload custom binary</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {samples.map((sample) => (
            <div
              key={sample.id}
              onClick={() => onSelectSample(sample.id)}
              className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 hover:bg-slate-850 cursor-pointer transition-all group flex flex-col justify-between"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                    {sample.category}
                  </span>
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded ${
                      sample.severity === 'CRITICAL'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                        : sample.severity === 'HIGH'
                        ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30'
                        : 'bg-yellow-500/10 text-yellow-400 border border-yellow-500/30'
                    }`}
                  >
                    {sample.severity}
                  </span>
                </div>
                <h4 className="text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
                  {sample.name}
                </h4>
                <p className="text-xs text-slate-400 leading-relaxed">
                  {sample.description}
                </p>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs text-cyan-400 font-mono">
                <span>Run Verification</span>
                <ArrowRight className="w-3.5 h-3.5 group-hover:translate-x-1 transition-transform" />
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};
