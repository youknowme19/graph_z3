import React, { useEffect, useRef, useState } from 'react';
import { Network, Layers, ChevronRight } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

const NODES = [
  { id: 0, addr: '0x1000004ac', name: 'main prologue', type: 'Entry Block', score: 0.12, status: 'BENIGN', color: 'text-slate-400', bg: 'bg-slate-900/50', border: 'border-slate-800' },
  { id: 1, addr: '0x10000051c', name: 'bounded copy sink', type: 'Vulnerability Sink', score: 0.94, status: 'CRITICAL RISK', color: 'text-red-300', bg: 'bg-red-950/30', border: 'border-red-500/40' },
  { id: 2, addr: '0x100000558', name: 'length validator', type: 'Branch Guard', score: 0.47, status: 'MEDIUM RISK', color: 'text-amber-300', bg: 'bg-amber-950/20', border: 'border-amber-600/30' },
  { id: 3, addr: '0x100000580', name: 'epilogue return', type: 'Exit Block', score: 0.08, status: 'NORMAL', color: 'text-emerald-400', bg: 'bg-emerald-950/20', border: 'border-emerald-800/30' },
];

export const StoryChapter1: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [progress, setProgress] = useState(0);
  const [activeNode, setActiveNode] = useState(1);

  useEffect(() => {
    const handleScroll = () => {
      if (!sectionRef.current) return;
      const rect = sectionRef.current.getBoundingClientRect();
      const h = sectionRef.current.offsetHeight - window.innerHeight;
      const p = Math.max(0, Math.min(1, -rect.top / h));
      setProgress(p);
      // Auto-cycle active node based on scroll
      const idx = Math.min(3, Math.floor(p * 4.5));
      setActiveNode(idx);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const node = NODES[activeNode];

  return (
    <div ref={sectionRef} className="relative" style={{ height: '300vh' }}>
      <div className="sticky top-0 h-screen flex flex-col overflow-hidden">
        {/* BG glow */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ background: 'radial-gradient(ellipse 70% 50% at 30% 50%, rgba(6,182,212,0.06) 0%, transparent 70%)' }} />

        <div className="relative z-10 flex flex-col h-full max-w-6xl mx-auto px-6 py-6 w-full gap-4">
          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <HoloSticker label="ACT II // NEURO-SYMBOLIC SYNTHESIS" sublabel="40-Dim SageConv GNN" variant="holographic"
                rotation={3} floatAnimation="tilt" icon={<Network className="w-4 h-4 text-cyan-300" />} />
            </div>
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-black text-slate-100 tracking-tight leading-tight">
              How GNNs Navigate the{' '}
              <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-indigo-400 bg-clip-text text-transparent">
                Binary Labyrinth
              </span>
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed max-w-xl mx-auto">
              GRAPH_Z3 compiles every binary into an attributed CFG. SageConv convolutions assign a vulnerability
              probability to each basic block — before symbolic execution even starts.
            </p>
          </div>

          {/* Progress */}
          <div className="w-full max-w-xs mx-auto">
            <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
              <div className="h-full bg-gradient-to-r from-cyan-500 to-indigo-500 rounded-full transition-all duration-200"
                style={{ width: `${progress * 100}%` }} />
            </div>
          </div>

          {/* Main content: left = CFG node list, right = deep dive */}
          <div className="flex-1 grid grid-cols-1 md:grid-cols-5 gap-5 min-h-0">
            {/* Node list */}
            <div className="md:col-span-2 flex flex-col gap-2.5 overflow-auto">
              <div className="flex items-center gap-2 font-mono text-[11px] text-slate-500 mb-1">
                <Layers className="w-3.5 h-3.5" />
                <span>CFG BASIC BLOCK EXPLORER</span>
              </div>
              {NODES.map((n) => (
                <button
                  key={n.id}
                  onClick={() => setActiveNode(n.id)}
                  className={`text-left p-4 rounded-2xl border transition-all ${n.bg} ${n.border} ${
                    activeNode === n.id ? 'scale-[1.02] ring-1 ring-cyan-400/30' : 'opacity-60 hover:opacity-80'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-mono text-[10px] text-slate-500">Block #{n.id}</span>
                    <span className={`font-mono text-[10px] font-bold px-1.5 py-0.5 rounded ${n.color} ${n.bg} border ${n.border}`}>
                      {(n.score * 100).toFixed(0)}% Risk
                    </span>
                  </div>
                  <div className={`font-mono text-xs font-bold ${n.color}`}>{n.addr}</div>
                  <div className="text-slate-500 text-[11px] mt-0.5">{n.name}</div>
                  <div className="flex items-center gap-1 mt-2">
                    <ChevronRight className={`w-3 h-3 transition-transform ${activeNode === n.id ? 'translate-x-1' : ''} ${n.color}`} />
                    <span className={`text-[10px] font-mono font-bold ${n.color}`}>{n.status}</span>
                  </div>
                </button>
              ))}
            </div>

            {/* Deep dive panel */}
            <div className="md:col-span-3 metamask-card rounded-3xl p-6 space-y-5 overflow-auto">
              <div className={`flex items-center justify-between border-b pb-3 ${node.border} border-opacity-40`}>
                <div>
                  <div className={`font-mono text-xs font-bold ${node.color}`}>{node.addr} // {node.name}</div>
                  <div className="text-slate-500 text-[11px] mt-0.5">{node.type}</div>
                </div>
                <span className={`text-[11px] font-mono font-bold px-2.5 py-1 rounded-lg ${node.color} ${node.bg} border ${node.border}`}>
                  {node.status}
                </span>
              </div>

              {/* Risk gauge */}
              <div className="space-y-2">
                <div className="flex justify-between text-[11px] font-mono">
                  <span className="text-slate-400">GNN Vulnerability Score</span>
                  <span className={`font-bold ${node.color}`}>{(node.score * 100).toFixed(1)}%</span>
                </div>
                <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{
                      width: `${node.score * 100}%`,
                      background: node.score > 0.8 ? 'linear-gradient(90deg, #ef4444, #f97316)' :
                        node.score > 0.4 ? 'linear-gradient(90deg, #f59e0b, #eab308)' :
                          'linear-gradient(90deg, #22d3ee, #10b981)',
                    }}
                  />
                </div>
              </div>

              {/* Feature vectors */}
              <div className="space-y-2">
                <span className="text-slate-500 text-[11px] font-mono uppercase tracking-wider block">
                  40-Dim Feature Vector (sampled)
                </span>
                <div className="flex flex-wrap gap-1.5">
                  {Array.from({ length: 20 }, (_, i) => {
                    const v = node.id === 1
                      ? [0.94, 0.88, 0.91, 0.76, 0.83, 0.90, 0.87, 0.72, 0.95, 0.68, 0.79, 0.85, 0.92, 0.77, 0.88, 0.94, 0.81, 0.73, 0.89, 0.84][i]
                      : node.id === 2
                        ? [0.47, 0.42, 0.51, 0.38, 0.44, 0.49, 0.36, 0.52, 0.41, 0.47, 0.43, 0.50, 0.39, 0.48, 0.45, 0.53, 0.40, 0.46, 0.42, 0.50][i]
                        : [0.12, 0.08, 0.15, 0.10, 0.09, 0.13, 0.07, 0.11, 0.14, 0.06, 0.10, 0.08, 0.12, 0.09, 0.11, 0.07, 0.13, 0.08, 0.10, 0.09][i];
                    return (
                      <div key={i} title={`Dim ${i}: ${v.toFixed(2)}`}
                        className="w-7 h-7 rounded-md flex items-center justify-center font-mono text-[8px] font-bold transition-all duration-500"
                        style={{
                          background: `rgba(6, 182, 212, ${v * 0.8})`,
                          color: v > 0.5 ? '#fff' : '#94a3b8',
                          border: `1px solid rgba(6,182,212,${v * 0.4})`,
                        }}>
                        {v.toFixed(1)}
                      </div>
                    );
                  })}
                  <div className="w-7 h-7 rounded-md flex items-center justify-center text-slate-600 font-mono text-[8px]">
                    +20
                  </div>
                </div>
              </div>

              {/* Symbolic engine action */}
              <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 font-mono text-xs space-y-1">
                <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Symbolic Engine Decision:</span>
                <p className="text-slate-300 leading-relaxed text-[11px]">
                  {node.id === 1
                    ? '→ HIGH PRIORITY SINK: angr initiates directed forward symbolic slice with tainted byte constraints. Z3 will prove reachability.'
                    : node.id === 2
                      ? '→ GUARD BRANCH: angr evaluates path constraint via Z3. Both true/false branches checked for safety invariant violations.'
                      : '→ LOW PRIORITY: Fast-forwarded via cached SimProcedures. No constraint solving needed for this block.'}
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
