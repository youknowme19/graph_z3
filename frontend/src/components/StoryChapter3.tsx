import React, { useEffect, useRef, useState } from 'react';
import { TerminalSquare, Zap, Copy, Check } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

const ATTACK_STEPS = [
  { num: '01', title: 'Taint Ingestion', desc: 'User payload bytes marked symbolic at stdin/network buffer entry point.', badge: 'BVS 40-Byte Vector', color: 'text-cyan-400', bg: 'bg-cyan-950/20', border: 'border-cyan-800/40' },
  { num: '02', title: 'Graph Traversal', desc: 'SageConv GNN steers angr toward unvalidated memory copy sink.', badge: 'Path Risk: 94.2%', color: 'text-purple-400', bg: 'bg-purple-950/20', border: 'border-purple-800/40' },
  { num: '03', title: 'Constraint Breach', desc: 'Destination buffer (8B) exceeded. Saved x30 register overwritten.', badge: 'STACK_SMASH_RIP', color: 'text-red-400', bg: 'bg-red-950/20', border: 'border-red-800/40' },
  { num: '04', title: 'Z3 SMT Solve', desc: 'Z3 synthesizes concrete model satisfying all branch path constraints.', badge: 'Z3 SAT (3.2 ms)', color: 'text-emerald-400', bg: 'bg-emerald-950/20', border: 'border-emerald-800/40' },
  { num: '05', title: 'PoC Generation', desc: 'Clean decimal byte array + 1-line Python reproducer command emitted.', badge: 'Executable PoC', color: 'text-amber-400', bg: 'bg-amber-950/20', border: 'border-amber-800/40' },
];

const PAYLOAD = [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, 32, 32, 2, 8, 32, 2, 4, 128, 2, 64, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15];

export const StoryChapter3: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      if (!sectionRef.current) return;
      const rect = sectionRef.current.getBoundingClientRect();
      const h = sectionRef.current.offsetHeight - window.innerHeight;
      const p = Math.max(0, Math.min(1, -rect.top / h));
      setActiveStep(Math.min(4, Math.floor(p * 5.5)));
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const handleCopy = () => {
    const cmd = `python3 -c "import sys; sys.stdout.buffer.write(bytes([${PAYLOAD.join(', ')}]))" | ./cwe120_buffer_overflow.bin`;
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const step = ATTACK_STEPS[activeStep];

  return (
    <div ref={sectionRef} className="relative" style={{ height: '280vh' }}>
      <div className="sticky top-0 h-screen flex flex-col overflow-hidden">
        {/* BG glow */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ background: 'radial-gradient(ellipse 70% 60% at 80% 60%, rgba(251,146,60,0.06) 0%, transparent 70%)' }} />

        <div className="relative z-10 flex flex-col h-full max-w-6xl mx-auto px-6 py-10 w-full gap-5">
          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <HoloSticker label="ACT IV // EXPLOIT PRIMITIVE SYNTHESIS" sublabel="From Proof to 100% Working PoC"
                variant="hazard" rotation={2} floatAnimation="tilt" icon={<Zap className="w-4 h-4 text-slate-950" />} />
            </div>
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-black text-slate-100 tracking-tight leading-tight">
              From Abstract Vuln to{' '}
              <span className="bg-gradient-to-r from-amber-400 via-orange-400 to-red-400 bg-clip-text text-transparent">
                Concrete Reproducer
              </span>
            </h2>
          </div>

          {/* Main: left=steps, right=terminal */}
          <div className="flex-1 grid grid-cols-1 md:grid-cols-5 gap-5 min-h-0">
            {/* Attack chain steps */}
            <div className="md:col-span-2 flex flex-col gap-2 overflow-auto">
              <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-1">Exploit Attack Chain</div>
              {ATTACK_STEPS.map((s, i) => (
                <button key={s.num} onClick={() => setActiveStep(i)}
                  className={`text-left p-3.5 rounded-2xl border transition-all ${s.bg} ${s.border} ${
                    activeStep === i ? 'scale-[1.02] ring-1 ring-white/10 shadow-lg' : 'opacity-50 hover:opacity-75'
                  }`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`font-mono text-lg font-black ${s.color}`}>{s.num}</span>
                    <span className={`text-[9px] font-mono font-bold px-1.5 py-0.5 rounded border ${s.color} ${s.bg} ${s.border}`}>
                      {s.badge}
                    </span>
                  </div>
                  <div className={`font-mono text-xs font-bold ${s.color}`}>{s.title}</div>
                  <p className="text-slate-500 text-[10px] leading-relaxed mt-0.5">{s.desc}</p>
                </button>
              ))}
            </div>

            {/* Terminal / payload panel */}
            <div className="md:col-span-3 flex flex-col gap-4 overflow-auto">
              {/* Active step detail */}
              <div className={`metamask-card rounded-3xl p-5 border ${step.border} space-y-3`}>
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-xl flex items-center justify-center font-mono font-black text-sm ${step.color} ${step.bg}`}>
                    {step.num}
                  </div>
                  <div>
                    <div className={`font-mono text-sm font-black ${step.color}`}>{step.title}</div>
                    <div className="text-slate-500 text-[11px]">Stage {parseInt(step.num)} of 5</div>
                  </div>
                  <span className={`ml-auto text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${step.color} ${step.bg} ${step.border}`}>
                    {step.badge}
                  </span>
                </div>
                <p className="text-slate-400 text-[12px] leading-relaxed font-mono">{step.desc}</p>

                {/* Progress bar */}
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${((activeStep + 1) / 5) * 100}%`,
                      background: 'linear-gradient(90deg, #22d3ee, #f59e0b, #ef4444)',
                    }} />
                </div>
              </div>

              {/* Z3 Payload */}
              <div className="metamask-card rounded-3xl p-5 space-y-4 flex-1">
                <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2 font-mono text-xs font-bold text-slate-300">
                    <TerminalSquare className="w-4 h-4 text-cyan-400" />
                    Z3 CONCRETE CRASH PAYLOAD
                  </div>
                  <span className="text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/60 text-[10px] font-bold">
                    SMT-SOLVED BREAKING POINT
                  </span>
                </div>

                {/* Byte array visual */}
                <div className="space-y-2">
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Z3 Decimal Integer Array (40 bytes):</div>
                  <div className="flex flex-wrap gap-1.5">
                    {PAYLOAD.map((byte, i) => (
                      <div key={i}
                        className="w-8 h-8 rounded-lg flex items-center justify-center font-mono text-[9px] font-bold transition-all duration-300"
                        style={{
                          background: `rgba(251, 146, 60, ${(byte / 255) * 0.6 + 0.1})`,
                          color: byte > 64 ? '#fff' : '#94a3b8',
                          border: `1px solid rgba(251,146,60,${(byte / 255) * 0.4 + 0.1})`,
                          transform: activeStep >= 4 ? 'scale(1)' : 'scale(0.8)',
                          opacity: activeStep >= 3 ? 1 : 0.3,
                        }}
                        title={`Byte ${i}: ${byte} (0x${byte.toString(16).padStart(2, '0')})`}
                      >
                        {byte}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Copy-able reproducer */}
                <div className="space-y-1.5">
                  <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Executable Python Reproducer:</div>
                  <div className="relative">
                    <pre className="p-3 rounded-xl bg-black/80 border border-slate-800 text-cyan-300 font-mono text-[10px] overflow-x-auto leading-relaxed select-all">
{`python3 -c "import sys; sys.stdout.buffer.write(bytes([${PAYLOAD.join(', ')}]))" | ./cwe120_buffer_overflow.bin`}
                    </pre>
                    <button onClick={handleCopy}
                      className="absolute top-2 right-2 p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 transition-all border border-slate-700 hover:border-cyan-500/40">
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 text-slate-400" />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
