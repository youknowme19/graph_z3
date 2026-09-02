import React, { useState } from 'react';
import { Network, Layers } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const StoryChapter1: React.FC = () => {
  const [activeNode, setActiveNode] = useState<number>(1);

  const sampleNodes = [
    {
      id: 0,
      name: '0x1000004ac // _main prologue',
      type: 'Entry Block',
      score: 0.12,
      features: ['Stack alloc: 64B', 'Frame setup', 'x29/x30 save'],
      status: 'BENIGN',
    },
    {
      id: 1,
      name: '0x10000051c // bounded copy call',
      type: 'Sink Vulnerability Candidate',
      score: 0.94,
      features: ['Tainted memory write', 'SimProc: strncpy', 'Unconstrained length arg'],
      status: 'HIGH RISK SINK',
    },
    {
      id: 2,
      name: '0x100000580 // epilogue return',
      type: 'Exit Block',
      score: 0.28,
      features: ['Register restore', 'ret instruction'],
      status: 'NORMAL',
    },
  ];

  return (
    <section className="relative py-16 space-y-12">
      <div className="flex justify-center">
        <HoloSticker
          label="ACT II // THE NEURO-SYMBOLIC SYNTHESIS"
          sublabel="40-Dimensional SageConv Graph Neural Network"
          variant="holographic"
          rotation={3}
          floatAnimation="tilt"
          icon={<Network className="w-4 h-4 text-cyan-300" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          How GNNs Navigate the{' '}
          <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
            Binary Labyrinth
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Instead of treating binaries as arbitrary byte streams, GRAPH_Z3 compiles the target into an attributed Control Flow Graph. Each basic block receives a 40-dimensional feature vector, and multi-layer SageConv convolutions compute non-linear risk priors.
        </p>
      </div>

      {/* Interactive GNN Explorer Card */}
      <div className="max-w-4xl mx-auto px-4">
        <div className="metamask-card rounded-3xl p-6 sm:p-8 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2.5 font-mono text-sm font-bold text-slate-200">
              <Layers className="w-4 h-4 text-cyan-400" />
              <span>CFG BASIC BLOCK TOPOLOGY EXPLORER</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/60">
                PyTorch Geometric SageConv
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {sampleNodes.map((node) => (
              <div
                key={node.id}
                onClick={() => setActiveNode(node.id)}
                className={`p-4 rounded-2xl border transition-all cursor-pointer space-y-2 ${
                  activeNode === node.id
                    ? 'bg-cyan-950/40 border-cyan-400/80 shadow-lg shadow-cyan-500/10 scale-[1.02]'
                    : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between text-[11px] font-mono">
                  <span className="text-slate-400">Node #{node.id}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded font-bold text-[10px] ${
                      node.score > 0.8
                        ? 'bg-red-950/80 text-red-300 border border-red-800/60'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    Risk: {(node.score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="font-mono text-xs font-bold text-slate-200 truncate">
                  {node.name}
                </div>
                <div className="text-[11px] text-slate-400">{node.type}</div>
              </div>
            ))}
          </div>

          {/* Active Node Deep-Dive Telemetry */}
          <div className="p-5 rounded-2xl bg-slate-950 border border-slate-800 font-mono text-xs space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div className="text-cyan-300 font-bold">
                Selected Block: {sampleNodes[activeNode].name}
              </div>
              <span className="text-[11px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                Status: {sampleNodes[activeNode].status}
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-2">
                <span className="text-slate-400 text-[11px] uppercase tracking-wider block">
                  Extracted Graph Features:
                </span>
                <ul className="space-y-1 text-slate-300">
                  {sampleNodes[activeNode].features.map((f, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <span className="text-cyan-400">•</span>
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div className="space-y-2">
                <span className="text-slate-400 text-[11px] uppercase tracking-wider block">
                  Symbolic Engine Action:
                </span>
                <p className="text-slate-300 text-[11px] leading-relaxed">
                  {activeNode === 1
                    ? 'Prioritized as target sink. angr initiates directed symbolic forward slice with tainted byte constraints.'
                    : 'Classified as low-priority utility block. Fast-forwarded via cached SimProcedures.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
