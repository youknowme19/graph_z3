import React, { useState } from 'react';
import { AlertTriangle, CheckCircle2, XCircle, Flame, Target, Cpu } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const StoryPrologue: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'traditional' | 'graph_z3'>('graph_z3');

  return (
    <section className="relative py-16 space-y-12">
      {/* Decorative Sticker */}
      <div className="flex justify-center">
        <HoloSticker
          label="ACT I // THE CRISIS OF BLIND FUZZING"
          sublabel="Why 90% of zero-days slip past CI/CD"
          variant="hazard"
          rotation={-2}
          floatAnimation="gentle"
          icon={<AlertTriangle className="w-4 h-4 text-slate-950" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          Software is Drowning in{' '}
          <span className="bg-gradient-to-r from-red-400 via-amber-400 to-yellow-400 bg-clip-text text-transparent">
            Path Explosion
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Traditional binary security tools force security engineers into an impossible trade-off: wait days for mutation fuzzers to guess branch conditions, or drown in thousands of false positives from static code linters.
        </p>
      </div>

      {/* Interactive Dilemma Visualizer */}
      <div className="max-w-4xl mx-auto px-4">
        {/* Toggle Switch */}
        <div className="flex justify-center mb-8">
          <div className="inline-flex p-1 rounded-2xl bg-slate-900 border border-slate-800">
            <button
              onClick={() => setActiveTab('traditional')}
              className={`px-5 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                activeTab === 'traditional'
                  ? 'bg-red-500/20 text-red-300 border border-red-500/30 shadow-lg'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Legacy Approach (AFL++ / Static Linters)
            </button>
            <button
              onClick={() => setActiveTab('graph_z3')}
              className={`px-5 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                activeTab === 'graph_z3'
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-lg'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              GRAPH_Z3 Neuro-Symbolic Approach
            </button>
          </div>
        </div>

        {activeTab === 'traditional' ? (
          <div className="metamask-card rounded-3xl p-6 sm:p-8 border-red-500/30 bg-gradient-to-br from-red-950/20 via-slate-900 to-slate-950 space-y-6">
            <div className="flex items-center justify-between border-b border-red-900/40 pb-4">
              <div className="flex items-center gap-3">
                <Flame className="w-5 h-5 text-red-400" />
                <span className="font-mono text-sm font-bold text-red-300">
                  MUTATION FUZZING & STATIC ANALYSIS BREAKDOWN
                </span>
              </div>
              <span className="text-[11px] font-mono text-red-400 bg-red-950/80 px-2.5 py-0.5 rounded border border-red-800">
                HIGH LATENCY / FALSE ALARMS
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
              <div className="p-4 rounded-xl bg-slate-950/60 border border-red-900/30 space-y-3">
                <div className="text-red-300 font-bold text-sm flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span>The Path Explosion Trap</span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  A program with just 50 if-statements creates <strong>1,125,899,906,842,624</strong> branches. AFL++ randomly bit-flips bytes hoping to satisfy `magic == 0x5a31`, wasting billions of CPU cycles in superficial loops.
                </p>
                <div className="p-2 rounded bg-red-950/40 text-red-400 text-[11px]">
                  Time to reach deep bug: <strong>48+ hours (or never)</strong>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/60 border border-red-900/30 space-y-3">
                <div className="text-red-300 font-bold text-sm flex items-center gap-2">
                  <XCircle className="w-4 h-4 text-red-400" />
                  <span>The False Positive Avalanche</span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Pattern-matching static linters flag hundreds of lines simply because `strcpy` or `sprintf` is present, even when memory bounds are guaranteed by prior sanity checks.
                </p>
                <div className="p-2 rounded bg-red-950/40 text-red-400 text-[11px]">
                  False Positive Ratio: <strong>Up to 92.4%</strong>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="metamask-card rounded-3xl p-6 sm:p-8 border-cyan-500/30 bg-gradient-to-br from-cyan-950/20 via-slate-900 to-slate-950 space-y-6">
            <div className="flex items-center justify-between border-b border-cyan-900/40 pb-4">
              <div className="flex items-center gap-3">
                <Target className="w-5 h-5 text-cyan-400" />
                <span className="font-mono text-sm font-bold text-cyan-300">
                  GRAPH_Z3 NEURO-SYMBOLIC CO-EXECUTION
                </span>
              </div>
              <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/80 px-2.5 py-0.5 rounded border border-emerald-800">
                0% FALSE POSITIVES / SECONDS TO EXPLOIT
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 font-mono text-xs">
              <div className="p-4 rounded-xl bg-slate-950/60 border border-cyan-900/30 space-y-3">
                <div className="text-cyan-300 font-bold text-sm flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>GNN-Guided Control Flow Steering</span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  A 40-dimensional SageConv Graph Neural Network ranks basic blocks by topological vulnerability probability, eliminating 85% of benign branches before symbolic execution starts.
                </p>
                <div className="p-2 rounded bg-cyan-950/40 text-cyan-300 text-[11px]">
                  Exploration Pruning: <strong>85.7% State Reduction</strong>
                </div>
              </div>

              <div className="p-4 rounded-xl bg-slate-950/60 border border-cyan-900/30 space-y-3">
                <div className="text-cyan-300 font-bold text-sm flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>Z3 SMT Invariant Verification</span>
                </div>
                <p className="text-slate-400 leading-relaxed">
                  Every vulnerability is mathematically verified by the Z3 theorem prover. If satisfiability is proved, Z3 synthesizes the exact crash payload bytes. If unprovable, zero warnings are emitted.
                </p>
                <div className="p-2 rounded bg-emerald-950/40 text-emerald-300 text-[11px]">
                  False Positive Rate: <strong>Mathematically Zero</strong>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </section>
  );
};
