import React, { useEffect, useRef, useState } from 'react';
import { ShieldCheck, Binary, Lock, Unlock } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

const PROOFS = [
  {
    key: 'stack_overflow',
    label: 'Vulnerable Path (SAT)',
    verdict: 'SATISFIABLE',
    verdictColor: 'text-red-300',
    verdictBg: 'bg-red-950/80 border-red-800',
    smtColor: 'text-purple-300',
    borderColor: 'border-red-900/30',
    icon: <Unlock className="w-4 h-4 text-red-400" />,
    formula: `; Path Constraint: user input length reaches copy sink
(assert (bvuge packet_len (_ bv64 64)))
; Safety Invariant: write size exceeds 8-byte stack buffer
(assert (bvugt copy_size (_ bv8 64)))
; Query the SMT solver
(check-sat)
; → sat
; Z3 Model:
;   packet_len = 64, copy_size = 72
;   payload    = [32,4,4,1,1,8,1,1,1,2,…,0]`,
    result: 'Vulnerability Formally Proved',
    resultDesc: 'Z3 synthesizes exact byte payload: [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, …] (40 bytes). Stack frame overwritten at byte 32. Return address hijacked.',
    resultColor: 'text-red-300',
  },
  {
    key: 'secure_invariant',
    label: 'Guarded Path (UNSAT)',
    verdict: 'UNSATISFIABLE',
    verdictColor: 'text-emerald-300',
    verdictBg: 'bg-emerald-950/80 border-emerald-800',
    smtColor: 'text-cyan-300',
    borderColor: 'border-emerald-900/30',
    icon: <Lock className="w-4 h-4 text-emerald-400" />,
    formula: `; Sanitization Guard active (branch checked first)
(assert (bvule copy_size (_ bv8 64)))
; Attempt to simultaneously prove OOB write
(assert (bvugt copy_size (_ bv8 64)))
; Query the SMT solver
(check-sat)
; → unsat
; Z3: No model exists — contradiction proved.`,
    result: 'Memory Safety Proved (0 Findings)',
    resultDesc: 'Z3 proved the two assertions are mutually exclusive under all possible inputs. No crash payload can exist. Zero false positive emitted.',
    resultColor: 'text-emerald-300',
  },
];

export const StoryChapter2: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [progress, setProgress] = useState(0);
  const [selectedProof, setSelectedProof] = useState<'stack_overflow' | 'secure_invariant'>('stack_overflow');
  const [animStep, setAnimStep] = useState(0); // drives typewriter

  useEffect(() => {
    const handleScroll = () => {
      if (!sectionRef.current) return;
      const rect = sectionRef.current.getBoundingClientRect();
      const h = sectionRef.current.offsetHeight - window.innerHeight;
      const p = Math.max(0, Math.min(1, -rect.top / h));
      setProgress(p);
      setAnimStep(Math.floor(p * 6));
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const proof = PROOFS.find(p => p.key === selectedProof)!;

  return (
    <div ref={sectionRef} className="relative" style={{ height: '280vh' }}>
      <div className="sticky top-0 h-screen flex flex-col overflow-hidden">
        {/* BG */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ background: 'radial-gradient(ellipse 70% 50% at 70% 40%, rgba(168,85,247,0.07) 0%, transparent 70%)' }} />

        <div className="relative z-10 flex flex-col h-full max-w-6xl mx-auto px-6 py-6 w-full gap-4">
          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <HoloSticker label="ACT III // MATHEMATICAL FORMAL VERIFICATION" sublabel="Z3 SMT Invariant Engine" variant="smt"
                rotation={-3} floatAnimation="gentle" icon={<ShieldCheck className="w-4 h-4 text-purple-300" />} />
            </div>
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-black text-slate-100 tracking-tight leading-tight">
              No Heuristics.{' '}
              <span className="bg-gradient-to-r from-purple-400 via-indigo-400 to-pink-400 bg-clip-text text-transparent">
                Pure First-Order Logic.
              </span>
            </h2>
          </div>

          {/* Toggle */}
          <div className="flex justify-center">
            <div className="inline-flex p-1 rounded-2xl bg-slate-900 border border-slate-800 gap-1">
              {PROOFS.map(p => (
                <button key={p.key}
                  onClick={() => setSelectedProof(p.key as any)}
                  className={`flex items-center gap-2 px-4 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                    selectedProof === p.key
                      ? p.key === 'stack_overflow'
                        ? 'bg-red-500/20 text-red-300 border border-red-500/40 shadow-lg'
                        : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-lg'
                      : 'text-slate-500 hover:text-slate-300'
                  }`}>
                  {p.icon}
                  {p.label}
                </button>
              ))}
            </div>
          </div>

          {/* Main content */}
          <div className="flex-1 grid grid-cols-1 md:grid-cols-2 gap-5 min-h-0">
            {/* SMT Formula */}
            <div className="metamask-card rounded-3xl p-5 space-y-4 overflow-auto">
              <div className={`flex items-center justify-between border-b pb-3 ${proof.borderColor} border-opacity-40`}>
                <div className="flex items-center gap-2 font-mono text-xs font-bold text-slate-300">
                  <Binary className="w-4 h-4 text-purple-400" />
                  SMT-LIB2 ASSERTION FORMULA
                </div>
                <span className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${proof.verdictBg} ${proof.verdictColor}`}>
                  Z3: {proof.verdict}
                </span>
              </div>

              <pre className={`p-4 rounded-xl bg-black/80 text-[11px] leading-loose overflow-x-auto ${proof.smtColor}`}>
                {proof.formula}
              </pre>

              {/* Animated step indicator */}
              <div className="grid grid-cols-3 gap-2">
                {['Parse Formula', 'Build Constraint Graph', 'DPLL(T) Solve', 'Model Extract', 'Synthesize Payload', 'Emit Report'].map((step, i) => (
                  <div key={step} className={`p-2 rounded-lg text-center transition-all duration-500 ${
                    i <= animStep
                      ? 'bg-purple-950/40 border border-purple-700/40 text-purple-300'
                      : 'bg-slate-900 border border-slate-800 text-slate-600'
                  }`}>
                    <div className="font-mono text-[9px] uppercase tracking-wider">{step}</div>
                    {i <= animStep && <div className="text-[8px] text-purple-400 mt-0.5">✓ done</div>}
                  </div>
                ))}
              </div>
            </div>

            {/* Result */}
            <div className="space-y-4 overflow-auto">
              {/* Verdict card */}
              <div className={`metamask-card rounded-3xl p-5 border ${proof.borderColor} space-y-3`}>
                <div className="flex items-center gap-3">
                  <div className={`w-12 h-12 rounded-2xl flex items-center justify-center text-2xl ${
                    selectedProof === 'stack_overflow' ? 'bg-red-950/60' : 'bg-emerald-950/60'
                  }`}>
                    {selectedProof === 'stack_overflow' ? '🔓' : '🔒'}
                  </div>
                  <div>
                    <div className={`font-mono text-sm font-black ${proof.resultColor}`}>{proof.result}</div>
                    <div className="text-slate-500 text-[11px] font-mono">Z3 v4.12 Theorem Prover</div>
                  </div>
                </div>
                <p className="text-slate-400 text-[12px] leading-relaxed font-mono">{proof.resultDesc}</p>
              </div>

              {/* Crash payload highlight (only for SAT) */}
              {selectedProof === 'stack_overflow' && (
                <div className="metamask-card rounded-3xl p-5 border border-cyan-500/20 space-y-3">
                  <div className="font-mono text-xs font-bold text-cyan-300 flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                    Z3 CONCRETE CRASH PAYLOAD
                  </div>
                  <div className="p-3 rounded-xl bg-black/80 font-mono text-[11px]">
                    <div className="text-slate-500 text-[10px] mb-1">// Exact decimal integers (40 bytes):</div>
                    <div className="text-cyan-300 font-bold break-all">
                      [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, 32, 32, 2, 8, 32, 2, 4, 128, 2, 64, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15]
                    </div>
                  </div>
                  <div className="p-3 rounded-xl bg-black/80 font-mono text-[10px] text-emerald-300">
                    python3 -c "import sys; sys.stdout.buffer.write(bytes([32,4,4,1,1,8,1,1,1,2,1,1,128,1,1,0,1,32,32,2,8,32,2,4,128,2,64,2,16,0,0,0,0,0,0,0,0,0,0,15]))" | ./target.bin
                  </div>
                </div>
              )}

              {/* Progress */}
              <div className="w-full">
                <div className="flex justify-between text-[10px] font-mono text-slate-600 mb-1">
                  <span>Scroll progress</span>
                  <span>{Math.round(progress * 100)}%</span>
                </div>
                <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-gradient-to-r from-purple-500 to-pink-500 rounded-full transition-all duration-200"
                    style={{ width: `${progress * 100}%` }} />
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
