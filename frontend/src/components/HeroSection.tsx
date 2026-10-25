import React from 'react';
import { ArrowRight, Terminal } from 'lucide-react';
import { CfgStage } from './CfgStage';

interface HeroSectionProps {
  onStartIntake: () => void;
  onSelectSample: (sampleId: string) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ onStartIntake, onSelectSample }) => {
  return (
    <section className="relative px-4 pt-12 pb-16 sm:px-6 lg:px-8 lg:pt-16 lg:pb-20">
      <div className="mx-auto max-w-7xl">
        <div className="grid grid-cols-1 items-center gap-12 lg:grid-cols-12">
          {/* Left Column: Minimalist Value Proposition */}
          <div className="space-y-6 lg:col-span-6">
            {/* Pill kicker */}
            <div className="inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-400">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
              <span>Neuro-Symbolic Binary Analysis · angr + Z3</span>
            </div>

            {/* Confident Headline */}
            <h1 className="text-4xl font-bold tracking-tight text-zinc-100 sm:text-5xl lg:text-[3.5rem] lg:leading-[1.1]">
              Rank the graph.
              <br />
              <span className="text-emerald-400">Prove the exploit.</span>
            </h1>

            {/* Concise, impactful subtext */}
            <p className="max-w-xl text-base leading-relaxed text-zinc-400 sm:text-lg">
              Conventional static analysis floods audits with false alarms, while blind symbolic execution explodes into millions of unreachable paths. GRAPH_Z3 uses GraphSAGE to prune 99.6% of benign blocks, then commands Z3 SMT to formally prove exploitability and synthesize concrete input payloads.
            </p>

            {/* Action buttons */}
            <div className="flex flex-wrap items-center gap-3 pt-2">
              <button
                type="button"
                onClick={onStartIntake}
                className="btn-signal group"
              >
                <span>Analyze Binary</span>
                <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-0.5" />
              </button>

              <button
                type="button"
                onClick={() => onSelectSample('cwe120_buffer_overflow')}
                className="btn-secondary"
              >
                <Terminal className="h-4 w-4 text-zinc-400" />
                <span>Launch CWE-120 Demo</span>
              </button>
            </div>

            {/* Proof Metrics Strip */}
            <div className="grid grid-cols-2 gap-3 pt-4 sm:grid-cols-4 border-t border-zinc-800/80">
              <div className="p-3 rounded-lg bg-zinc-900/40 border border-zinc-800/60">
                <span className="block font-mono text-[10px] uppercase text-zinc-500 font-semibold tracking-wider">
                  Verified FPs
                </span>
                <span className="text-2xl font-bold font-mono text-emerald-400 mt-1 block">
                  0.0%
                </span>
                <span className="text-[10px] text-zinc-500">Formal SMT proof</span>
              </div>

              <div className="p-3 rounded-lg bg-zinc-900/40 border border-zinc-800/60">
                <span className="block font-mono text-[10px] uppercase text-zinc-500 font-semibold tracking-wider">
                  Path Pruning
                </span>
                <span className="text-2xl font-bold font-mono text-zinc-100 mt-1 block">
                  99.66%
                </span>
                <span className="text-[10px] text-zinc-500">GraphSAGE ranking</span>
              </div>

              <div className="p-3 rounded-lg bg-zinc-900/40 border border-zinc-800/60">
                <span className="block font-mono text-[10px] uppercase text-zinc-500 font-semibold tracking-wider">
                  Speedup
                </span>
                <span className="text-2xl font-bold font-mono text-zinc-100 mt-1 block">
                  60.2×
                </span>
                <span className="text-[10px] text-zinc-500">vs unguided search</span>
              </div>

              <div className="p-3 rounded-lg bg-zinc-900/40 border border-zinc-800/60">
                <span className="block font-mono text-[10px] uppercase text-zinc-500 font-semibold tracking-wider">
                  Z3 Latency
                </span>
                <span className="text-2xl font-bold font-mono text-zinc-100 mt-1 block">
                  27 ms
                </span>
                <span className="text-[10px] text-zinc-500">Mean SAT solve time</span>
              </div>
            </div>
          </div>

          {/* Right Column: Sleek 3D Control Flow Graph */}
          <div className="lg:col-span-6">
            <CfgStage />
            <div className="mt-3 flex items-center justify-between text-xs text-zinc-500 font-mono px-1">
              <span>Target: cwe120_buffer_overflow.bin</span>
              <span>Arch: AArch64 · VEX IR</span>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
