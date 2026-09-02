import React, { useState } from 'react';
import { ArrowRight, TerminalSquare, ShieldCheck, Cpu, Code2, Sparkles } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

interface HeroSectionProps {
  onStartIntake: () => void;
  onSelectSample: (sampleId: string) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({
  onStartIntake,
  onSelectSample,
}) => {
  const [mouseCoord, setMouseCoord] = useState({ x: 0, y: 0 });
  const [isHovered, setIsHovered] = useState(false);

  const handleHeroMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setMouseCoord({ x, y });
  };

  return (
    <section
      onMouseMove={handleHeroMouseMove}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => {
        setIsHovered(false);
        setMouseCoord({ x: 0, y: 0 });
      }}
      className="relative pt-6 pb-20 overflow-visible"
    >
      {/* ── Floating Decorative Stickers (MetaMask Style) ────────────────── */}
      <div className="absolute -top-4 left-4 sm:left-12 z-20 pointer-events-auto">
        <HoloSticker
          label="Z3 SMT VERIFIED"
          sublabel="Formal Invariant SAT"
          variant="smt"
          rotation={-6}
          floatAnimation="tilt"
          floatDelay={0.2}
          icon={<ShieldCheck className="w-4 h-4 text-purple-300" />}
        />
      </div>

      <div className="absolute top-2 right-4 sm:right-16 z-20 pointer-events-auto">
        <HoloSticker
          label="0.0% FALSE POSITIVES"
          sublabel="Mathematically Sound"
          variant="secure"
          rotation={5}
          floatAnimation="gentle"
          floatDelay={0.6}
          icon={<Sparkles className="w-4 h-4 text-emerald-300" />}
        />
      </div>

      <div className="absolute -bottom-6 left-8 sm:left-24 z-20 pointer-events-auto hidden md:block">
        <HoloSticker
          label="SAGE-CONV GNN"
          sublabel="40-Dim CFG Embedding"
          variant="holographic"
          rotation={-3}
          floatAnimation="orbit"
          floatDelay={1.2}
          icon={<Cpu className="w-4 h-4 text-pink-300" />}
        />
      </div>

      <div className="absolute -bottom-4 right-8 sm:right-28 z-20 pointer-events-auto hidden md:block">
        <HoloSticker
          label="EXPLOIT CHAIN GEN"
          sublabel="Concrete Byte Reproducers"
          variant="hazard"
          rotation={4}
          floatAnimation="gentle"
          floatDelay={0.8}
          icon={<Code2 className="w-4 h-4 text-slate-900" />}
        />
      </div>

      {/* ── Main Hero Typography & Story Arc ──────────────────────────────── */}
      <div className="text-center space-y-6 max-w-4xl mx-auto px-4">
        <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-slate-900/90 border border-slate-700/80 shadow-inner backdrop-blur-md">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span className="text-xs font-mono font-bold tracking-wider text-cyan-300 uppercase">
            Next-Gen Neuro-Symbolic Binary Fuzzer
          </span>
        </div>

        <h1 className="text-4xl sm:text-6xl lg:text-7xl font-black tracking-tight text-white leading-[1.08] font-sans">
          Eliminate Blind Fuzzing.{' '}
          <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 bg-clip-text text-transparent">
            Mathematically Prove
          </span>{' '}
          Every Exploit.
        </h1>

        <p className="text-base sm:text-lg text-slate-300 leading-relaxed max-w-2xl mx-auto font-sans font-normal">
          Legacy fuzzers waste days mutating random inputs into dead ends. <strong className="text-white font-semibold">GRAPH_Z3</strong> pairs Graph Neural Networks with Z3 SMT constraint solving to hunt zero-days, prove reachability, and generate exact crash payloads in seconds.
        </p>

        {/* Hero CTAs */}
        <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
          <button
            onClick={onStartIntake}
            className="group relative flex items-center gap-3 px-7 py-4 rounded-2xl bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-black text-sm tracking-wider uppercase transition-all shadow-xl shadow-cyan-500/25 hover:shadow-cyan-500/40 hover:scale-[1.02] active:scale-[0.98]"
          >
            <span>Analyze Target Binary</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1.5 transition-transform" />
          </button>

          <button
            onClick={() => onSelectSample('cwe120_buffer_overflow')}
            className="flex items-center gap-2.5 px-6 py-4 rounded-2xl bg-slate-900/90 hover:bg-slate-800/90 text-slate-200 hover:text-white border border-slate-700/80 hover:border-cyan-400/50 text-sm font-bold tracking-wide transition-all shadow-lg hover:scale-[1.01]"
          >
            <TerminalSquare className="w-4 h-4 text-cyan-400" />
            <span>Launch Buffer Overflow Demo</span>
          </button>
        </div>
      </div>

      {/* ── 3D Perspective Interactive Showcase Card ───────────────────────── */}
      <div className="mt-14 max-w-4xl mx-auto px-4">
        <div
          style={{
            transform: isHovered
              ? `perspective(1000px) rotateX(${-mouseCoord.y * 8}deg) rotateY(${mouseCoord.x * 12}deg) scale3d(1.01, 1.01, 1.01)`
              : 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)',
            transition: isHovered ? 'transform 0.1s ease-out' : 'transform 0.5s ease-out',
          }}
          className="metamask-card rounded-3xl p-6 sm:p-8 relative overflow-hidden group"
        >
          {/* Subtle glowing reflection line across card */}
          <div className="absolute -top-32 left-1/2 -translate-x-1/2 w-[120%] h-48 bg-gradient-to-b from-cyan-400/10 via-purple-500/5 to-transparent rounded-full blur-2xl pointer-events-none" />

          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4 mb-6 font-mono text-xs">
            <div className="flex items-center gap-2 text-slate-300 font-bold">
              <span className="w-3 h-3 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50" />
              <span>LIVE_ENGINE // FORMAL_VERIFICATION_LAB</span>
            </div>
            <div className="flex items-center gap-2 text-slate-400">
              <span className="px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700">AARCH64</span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-purple-300 border border-slate-700">Z3-SMT v4.12</span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-emerald-300 border border-slate-700">100% SOUND</span>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
            {/* Stage 1: CFG Extraction */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
              <span className="text-[10px] text-cyan-400 font-bold uppercase tracking-wider block">01. Neural Graph</span>
              <div className="text-slate-200 font-bold text-sm">SageConv GNN</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Extracts 40-dim topological embeddings across 31 basic blocks to prioritize high-risk paths.
              </p>
            </div>

            {/* Stage 2: SMT Theorem Prover */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
              <span className="text-[10px] text-purple-400 font-bold uppercase tracking-wider block">02. Formal Solver</span>
              <div className="text-slate-200 font-bold text-sm">Z3 Theorem Prover</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Evaluates path predicates & memory safety invariants. Returns mathematical proof of satisfiability.
              </p>
            </div>

            {/* Stage 3: Exploit Synthesizer */}
            <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
              <span className="text-[10px] text-emerald-400 font-bold uppercase tracking-wider block">03. Exact Payload</span>
              <div className="text-slate-200 font-bold text-sm">Crash Vector Gen</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                Generates precise decimal integer crash vectors `[32, 4, 4, ...]` that reproduce the breach 100% cleanly.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
