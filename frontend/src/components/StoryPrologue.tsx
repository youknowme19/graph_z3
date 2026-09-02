import React, { useEffect, useRef, useState } from 'react';
import { AlertTriangle, CheckCircle2, XCircle, Flame, Target, ArrowDown } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

/* ── Sticky-scroll storytelling section mimicking MetaMask's approach ── */
export const StoryPrologue: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [progress, setProgress] = useState(0); // 0–1 scroll progress within section
  const [activeTab, setActiveTab] = useState<'traditional' | 'graph_z3'>('traditional');

  useEffect(() => {
    const handleScroll = () => {
      if (!sectionRef.current) return;
      const rect = sectionRef.current.getBoundingClientRect();
      const sectionHeight = sectionRef.current.offsetHeight - window.innerHeight;
      const scrolled = -rect.top;
      const p = Math.max(0, Math.min(1, scrolled / sectionHeight));
      setProgress(p);
      // Auto-switch tab at 60% scroll
      setActiveTab(p >= 0.6 ? 'graph_z3' : 'traditional');
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  // Derived visual states from scroll
  const leftOpacity = activeTab === 'traditional' ? 1 : 0.25;
  const rightOpacity = activeTab === 'graph_z3' ? 1 : 0.25;

  return (
    <div ref={sectionRef} className="relative" style={{ height: '250vh' }}>
      {/* Sticky viewport-filling panel */}
      <div className="sticky top-0 h-screen flex flex-col overflow-hidden">
        {/* Background atmosphere */}
        <div
          className="absolute inset-0 pointer-events-none transition-all duration-700"
          style={{
            background: activeTab === 'traditional'
              ? 'radial-gradient(ellipse 80% 60% at 50% 30%, rgba(239,68,68,0.08) 0%, transparent 70%)'
              : 'radial-gradient(ellipse 80% 60% at 50% 30%, rgba(6,182,212,0.08) 0%, transparent 70%)',
          }}
        />

        <div className="relative z-10 flex flex-col h-full max-w-6xl mx-auto px-6 py-12 w-full">
          {/* ── Top header ───────────────────────────────────────────── */}
          <div className="text-center mb-8 space-y-4">
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
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-black text-slate-100 tracking-tight leading-tight">
              Software is Drowning in{' '}
              <span className="bg-gradient-to-r from-red-400 via-amber-400 to-yellow-400 bg-clip-text text-transparent">
                Path Explosion
              </span>
            </h2>
            <p className="text-slate-400 text-sm sm:text-base leading-relaxed max-w-2xl mx-auto">
              Traditional tools force an impossible trade-off: wait days for mutation fuzzers to guess branch
              conditions, or drown in thousands of false positives from static linters.
            </p>
          </div>

          {/* ── Scroll progress bar ───────────────────────────────────── */}
          <div className="w-full max-w-md mx-auto mb-8">
            <div className="flex items-center justify-between mb-2 text-[11px] font-mono">
              <span className={`transition-colors ${activeTab === 'traditional' ? 'text-red-400' : 'text-slate-600'}`}>
                LEGACY APPROACH
              </span>
              <span className={`transition-colors ${activeTab === 'graph_z3' ? 'text-cyan-400' : 'text-slate-600'}`}>
                GRAPH_Z3 APPROACH
              </span>
            </div>
            <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-300"
                style={{
                  width: `${progress * 100}%`,
                  background: activeTab === 'traditional'
                    ? 'linear-gradient(90deg, #ef4444, #f59e0b)'
                    : 'linear-gradient(90deg, #22d3ee, #06b6d4)',
                }}
              />
            </div>
            <p className="text-center text-[10px] text-slate-600 font-mono mt-1">scroll to compare →</p>
          </div>

          {/* ── Side-by-side comparison cards ────────────────────────── */}
          <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-5 min-h-0">
            {/* Left: Traditional/Legacy */}
            <div
              className="metamask-card rounded-3xl p-6 border-red-500/20 bg-gradient-to-br from-red-950/15 via-slate-900 to-slate-950 space-y-4 overflow-auto transition-all duration-500"
              style={{ opacity: leftOpacity, transform: `scale(${leftOpacity === 1 ? 1 : 0.97})` }}
            >
              <div className="flex items-center justify-between border-b border-red-900/40 pb-3">
                <div className="flex items-center gap-2.5">
                  <Flame className="w-5 h-5 text-red-400" />
                  <span className="font-mono text-xs font-bold text-red-300">LEGACY: AFL++ / Static Linters</span>
                </div>
                <span className="text-[10px] font-mono text-red-400 bg-red-950/80 px-2 py-0.5 rounded border border-red-800">
                  ✗ HIGH LATENCY
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                {[
                  { title: 'Path Explosion Trap', body: 'A program with just 50 if-statements creates 1,125,899,906,842,624 branches. AFL++ bit-flips hoping to satisfy `magic == 0x5a31` — wasting billions of CPU cycles.', stat: '48+ hours (or never)', statColor: 'text-red-300 bg-red-950/40' },
                  { title: 'False Positive Avalanche', body: 'Pattern-matching linters flag hundreds of `strcpy` calls even when memory bounds are guaranteed by prior sanity checks.', stat: 'Up to 92.4% false positives', statColor: 'text-amber-300 bg-amber-950/40' },
                  { title: 'No Crash Reproducers', body: 'Even when a crash is found, mutation fuzzers produce opaque blobs — not clean, minimal byte sequences that engineers can reason about.', stat: '0 actionable payloads', statColor: 'text-red-300 bg-red-950/40' },
                ].map((item) => (
                  <div key={item.title} className="p-3 rounded-xl bg-slate-950/60 border border-red-900/20 space-y-1.5">
                    <div className="text-red-300 font-bold flex items-center gap-2">
                      <XCircle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                      <span>{item.title}</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed text-[11px]">{item.body}</p>
                    <div className={`text-[10px] px-2 py-0.5 rounded inline-block ${item.statColor}`}>{item.stat}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right: GRAPH_Z3 */}
            <div
              className="metamask-card rounded-3xl p-6 border-cyan-500/20 bg-gradient-to-br from-cyan-950/15 via-slate-900 to-slate-950 space-y-4 overflow-auto transition-all duration-500"
              style={{ opacity: rightOpacity, transform: `scale(${rightOpacity === 1 ? 1 : 0.97})` }}
            >
              <div className="flex items-center justify-between border-b border-cyan-900/40 pb-3">
                <div className="flex items-center gap-2.5">
                  <Target className="w-5 h-5 text-cyan-400" />
                  <span className="font-mono text-xs font-bold text-cyan-300">GRAPH_Z3 Neuro-Symbolic Engine</span>
                </div>
                <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                  ✓ SECONDS TO EXPLOIT
                </span>
              </div>

              <div className="space-y-3 font-mono text-xs">
                {[
                  { title: 'GNN-Guided CFG Steering', body: 'A 40-dim SageConv GNN ranks basic blocks by vulnerability probability, eliminating 85% of benign paths before symbolic execution starts.', stat: '85.7% state space reduction', statColor: 'text-cyan-300 bg-cyan-950/40' },
                  { title: 'Z3 SMT Invariant Proofs', body: 'Every potential vulnerability is formally verified by Z3. If satisfiability is UNSAT, zero warnings are emitted — no noise.', stat: 'Mathematically zero false positives', statColor: 'text-emerald-300 bg-emerald-950/40' },
                  { title: 'Exact Crash Payload Synthesis', body: 'When Z3 proves SAT, it synthesizes the exact decimal integer byte sequence [32, 4, 4, 1, ...] that triggers the breach — 100% reproducible.', stat: 'Concrete bytes in < 3 seconds', statColor: 'text-cyan-300 bg-cyan-950/40' },
                ].map((item) => (
                  <div key={item.title} className="p-3 rounded-xl bg-slate-950/60 border border-cyan-900/20 space-y-1.5">
                    <div className="text-cyan-300 font-bold flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                      <span>{item.title}</span>
                    </div>
                    <p className="text-slate-400 leading-relaxed text-[11px]">{item.body}</p>
                    <div className={`text-[10px] px-2 py-0.5 rounded inline-block ${item.statColor}`}>{item.stat}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* ── Scroll hint at bottom ─────────────────────────────────── */}
          <div className="text-center mt-4 flex items-center justify-center gap-2 text-slate-600">
            <ArrowDown className="w-3.5 h-3.5 animate-bounce" />
            <span className="text-[10px] font-mono">scroll further to see the neuro-symbolic engine in action</span>
            <ArrowDown className="w-3.5 h-3.5 animate-bounce" />
          </div>
        </div>
      </div>
    </div>
  );
};
