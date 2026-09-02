import React, { useState, useEffect, useRef } from 'react';
import { ArrowRight, TerminalSquare, ShieldCheck, Cpu, Code2, Sparkles, Zap } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

interface HeroSectionProps {
  onStartIntake: () => void;
  onSelectSample: (sampleId: string) => void;
}

export const HeroSection: React.FC<HeroSectionProps> = ({ onStartIntake, onSelectSample }) => {
  const [scrollY, setScrollY] = useState(0);
  const [mouseCoord, setMouseCoord] = useState({ x: 0, y: 0 });
  const heroRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const onScroll = () => setScrollY(window.scrollY);
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const handleMouseMove = (e: React.MouseEvent<HTMLElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setMouseCoord({ x, y });
  };

  // Parallax coefficients for different layers
  const parallax1 = scrollY * 0.4;
  const parallax2 = scrollY * 0.25;
  const parallax3 = scrollY * 0.15;
  const heroOpacity = Math.max(0, 1 - scrollY / 600);
  const heroScale = 1 - scrollY * 0.0003;

  return (
    <section
      ref={heroRef}
      onMouseMove={handleMouseMove}
      className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden"
      style={{ perspective: '1200px' }}
    >
      {/* ── LAYER 0: Radial atmosphere blobs (deep parallax) ──────────── */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ transform: `translateY(${parallax1}px)` }}
      >
        <div className="absolute top-[10%] left-[15%] w-[600px] h-[600px] rounded-full opacity-30"
          style={{ background: 'radial-gradient(circle, rgba(6,182,212,0.25) 0%, transparent 70%)' }} />
        <div className="absolute top-[40%] right-[10%] w-[500px] h-[500px] rounded-full opacity-20"
          style={{ background: 'radial-gradient(circle, rgba(168,85,247,0.3) 0%, transparent 70%)' }} />
        <div className="absolute bottom-[5%] left-[30%] w-[400px] h-[400px] rounded-full opacity-15"
          style={{ background: 'radial-gradient(circle, rgba(236,72,153,0.25) 0%, transparent 70%)' }} />
      </div>

      {/* ── LAYER 1: Grid overlay (medium parallax) ───────────────────── */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          transform: `translateY(${parallax2}px) translateX(${mouseCoord.x * -12}px)`,
          backgroundImage: `
            linear-gradient(rgba(56,189,248,0.04) 1px, transparent 1px),
            linear-gradient(90deg, rgba(56,189,248,0.04) 1px, transparent 1px)
          `,
          backgroundSize: '64px 64px',
        }}
      />

      {/* ── LAYER 2: Floating stickers (shallow parallax) ─────────────── */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{ transform: `translateY(${parallax3}px)` }}
      >
        {/* Top-left sticker */}
        <div className="absolute top-[18%] left-[8%] pointer-events-auto"
          style={{ transform: `translateX(${mouseCoord.x * -18}px) translateY(${mouseCoord.y * -10}px)` }}>
          <HoloSticker label="Z3 SMT VERIFIED" sublabel="Formal Invariant SAT" variant="smt"
            rotation={-8} floatAnimation="tilt" floatDelay={0.2}
            icon={<ShieldCheck className="w-4 h-4 text-purple-300" />} />
        </div>

        {/* Top-right sticker */}
        <div className="absolute top-[22%] right-[8%] pointer-events-auto"
          style={{ transform: `translateX(${mouseCoord.x * 20}px) translateY(${mouseCoord.y * -8}px)` }}>
          <HoloSticker label="0.0% FALSE POSITIVES" sublabel="Mathematically Sound" variant="secure"
            rotation={6} floatAnimation="gentle" floatDelay={0.5}
            icon={<Sparkles className="w-4 h-4 text-emerald-300" />} />
        </div>

        {/* Bottom-left sticker */}
        <div className="absolute bottom-[22%] left-[6%] pointer-events-auto hidden md:block"
          style={{ transform: `translateX(${mouseCoord.x * -14}px) translateY(${mouseCoord.y * 12}px)` }}>
          <HoloSticker label="SAGE-CONV GNN" sublabel="40-Dim CFG Embedding" variant="holographic"
            rotation={-4} floatAnimation="orbit" floatDelay={1.0}
            icon={<Cpu className="w-4 h-4 text-pink-300" />} />
        </div>

        {/* Bottom-right sticker */}
        <div className="absolute bottom-[20%] right-[7%] pointer-events-auto hidden md:block"
          style={{ transform: `translateX(${mouseCoord.x * 16}px) translateY(${mouseCoord.y * 10}px)` }}>
          <HoloSticker label="EXPLOIT CHAIN GEN" sublabel="Concrete Byte Reproducers" variant="hazard"
            rotation={5} floatAnimation="gentle" floatDelay={0.8}
            icon={<Code2 className="w-4 h-4 text-slate-900" />} />
        </div>

        {/* Centre-left floating badge */}
        <div className="absolute top-[50%] left-[3%] pointer-events-auto hidden lg:block"
          style={{ transform: `translateX(${mouseCoord.x * -22}px) translateY(${mouseCoord.y * 5}px)` }}>
          <HoloSticker label="angr + Z3" sublabel="Symbolic Co-Execution" variant="cyber"
            rotation={-12} floatAnimation="tilt" floatDelay={1.4}
            icon={<Zap className="w-4 h-4 text-cyan-300" />} />
        </div>
      </div>

      {/* ── LAYER 3: Main hero content ─────────────────────────────────── */}
      <div
        className="relative z-10 text-center max-w-5xl mx-auto px-6 space-y-8"
        style={{
          opacity: heroOpacity,
          transform: `scale(${heroScale}) translateY(${-parallax2 * 0.3}px) rotateX(${mouseCoord.y * 1.5}deg) rotateY(${mouseCoord.x * 1.5}deg)`,
          transition: 'transform 0.15s ease-out',
        }}
      >
        {/* Category pill */}
        <div className="inline-flex items-center gap-2.5 px-4 py-1.5 rounded-full bg-slate-900/90 border border-slate-700/80 shadow-inner backdrop-blur-md">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-400" />
          </span>
          <span className="text-xs font-mono font-bold tracking-widest text-cyan-300 uppercase">
            Next-Gen Neuro-Symbolic Binary Fuzzer
          </span>
        </div>

        {/* Giant headline — MetaMask style */}
        <h1 className="text-5xl sm:text-7xl lg:text-[96px] font-black tracking-[-0.03em] text-white leading-[0.95] font-sans">
          <span className="block">Eliminate</span>
          <span className="block bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 bg-clip-text text-transparent pb-2">
            Blind Fuzzing.
          </span>
          <span className="block text-slate-300">Prove Every</span>
          <span className="block bg-gradient-to-r from-purple-400 via-pink-400 to-rose-400 bg-clip-text text-transparent">
            Exploit.
          </span>
        </h1>

        {/* Sub-headline */}
        <p className="text-base sm:text-xl text-slate-400 leading-relaxed max-w-2xl mx-auto font-sans font-normal">
          Legacy fuzzers waste days mutating random bytes into dead ends.{' '}
          <strong className="text-slate-200 font-semibold">GRAPH_Z3</strong> pairs SageConv Graph Neural Networks with Z3 SMT solving to hunt zero-days,
          prove reachability, and generate exact crash payloads in <strong className="text-cyan-400">seconds</strong>.
        </p>

        {/* CTA row */}
        <div className="flex flex-wrap items-center justify-center gap-4 pt-2">
          <button
            onClick={onStartIntake}
            className="group relative flex items-center gap-3 px-8 py-4 rounded-2xl bg-gradient-to-r from-cyan-500 via-blue-500 to-indigo-600 hover:from-cyan-400 hover:to-indigo-500 text-slate-950 font-black text-sm tracking-wider uppercase transition-all shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 hover:scale-[1.04] active:scale-[0.97]"
          >
            <span>Analyze Target Binary</span>
            <ArrowRight className="w-4 h-4 group-hover:translate-x-1.5 transition-transform" />
            {/* Glow ring */}
            <span className="absolute inset-0 rounded-2xl ring-2 ring-cyan-400/0 group-hover:ring-cyan-400/60 transition-all" />
          </button>

          <button
            onClick={() => onSelectSample('cwe120_buffer_overflow')}
            className="flex items-center gap-2.5 px-7 py-4 rounded-2xl bg-white/5 hover:bg-white/10 text-slate-200 hover:text-white border border-white/10 hover:border-cyan-400/40 text-sm font-bold tracking-wide transition-all shadow-lg backdrop-blur-sm hover:scale-[1.02]"
          >
            <TerminalSquare className="w-4 h-4 text-cyan-400" />
            <span>Launch Buffer Overflow Demo</span>
          </button>
        </div>

        {/* Stats row */}
        <div className="flex flex-wrap items-center justify-center gap-8 pt-4">
          {[
            { value: '0%', label: 'False Positives', color: 'text-emerald-400' },
            { value: '<3s', label: 'To First Exploit', color: 'text-cyan-400' },
            { value: '100%', label: 'Mathematically Sound', color: 'text-purple-400' },
            { value: '85%', label: 'State Space Pruning', color: 'text-pink-400' },
          ].map((stat) => (
            <div key={stat.label} className="text-center">
              <div className={`text-3xl font-black font-mono ${stat.color}`}>{stat.value}</div>
              <div className="text-xs text-slate-500 font-mono uppercase tracking-wider mt-0.5">{stat.label}</div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Scroll indicator ──────────────────────────────────────────── */}
      <div
        className="absolute bottom-10 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2"
        style={{ opacity: heroOpacity }}
      >
        <span className="text-[10px] font-mono text-slate-500 tracking-widest uppercase">Scroll to explore</span>
        <div className="w-5 h-8 rounded-full border border-slate-700 flex items-start justify-center p-1">
          <div className="w-1 h-2 bg-cyan-400 rounded-full animate-bounce" />
        </div>
      </div>
    </section>
  );
};

// Parallax scroll layers: heroOpacity fades content out as user scrolls into first chapter
