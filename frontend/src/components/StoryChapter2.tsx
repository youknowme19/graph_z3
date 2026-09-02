import React, { useState } from 'react';
import { ShieldCheck, CheckCircle2, Binary, Terminal, Code2 } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const StoryChapter2: React.FC = () => {
  const [selectedProof, setSelectedProof] = useState<'stack_overflow' | 'secure_invariant'>('stack_overflow');

  return (
    <section className="relative py-16 space-y-12">
      <div className="flex justify-center">
        <HoloSticker
          label="ACT III // MATHEMATICAL FORMAL VERIFICATION"
          sublabel="Z3 SMT Invariant Verification Engine"
          variant="smt"
          rotation={-3}
          floatAnimation="gentle"
          icon={<ShieldCheck className="w-4 h-4 text-purple-300" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          No Heuristics.{' '}
          <span className="bg-gradient-to-r from-purple-400 via-indigo-400 to-pink-400 bg-clip-text text-transparent">
            Pure First-Order Logic.
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Every potential vulnerability is formalized into a mathematical assertion. The Z3 Theorem Prover checks whether any possible input vector can satisfy the path condition while simultaneously violating memory safety invariants.
        </p>
      </div>

      {/* Interactive SMT Solver Visualizer */}
      <div className="max-w-4xl mx-auto px-4">
        <div className="metamask-card rounded-3xl p-6 sm:p-8 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2 font-mono text-sm font-bold text-slate-200">
              <Binary className="w-4 h-4 text-purple-400" />
              <span>SMT FORMULA SATISFIABILITY VERIFIER</span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setSelectedProof('stack_overflow')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
                  selectedProof === 'stack_overflow'
                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Vulnerable Path (SAT)
              </button>
              <button
                onClick={() => setSelectedProof('secure_invariant')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
                  selectedProof === 'secure_invariant'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Guarded Path (UNSAT)
              </button>
            </div>
          </div>

          {selectedProof === 'stack_overflow' ? (
            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-slate-950 border border-red-900/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-red-400 font-bold uppercase text-[11px]">
                    SMT-LIB2 Assertion Formula:
                  </span>
                  <span className="px-2 py-0.5 rounded bg-red-950 text-red-300 border border-red-800 font-bold text-[10px]">
                    Z3 VERDICT: SATISFIABLE (SAT)
                  </span>
                </div>
                <pre className="p-3 rounded-lg bg-black text-purple-300 overflow-x-auto text-[11px] leading-relaxed">
{`; Path Constraint: User input length must reach copy sink
(assert (bvuge packet_len (_ bv32 64)))
; Safety Invariant Violation: write size exceeds stack buffer (8 bytes)
(assert (bvugt copy_size (_ bv8 64)))
; Memory Safety Assertion:
(check-sat)`}
                </pre>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <span className="text-slate-400 text-[10px] uppercase font-bold block">
                    Z3 Evaluated Counterexample Model:
                  </span>
                  <div className="text-emerald-400 font-bold text-xs break-all">
                    packet_payload = [32, 4, 4, 1, 1, 8, ...] (40 Bytes)
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Exact input that overwrites saved frame pointer and return address.
                  </div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                  <span className="text-slate-400 text-[10px] uppercase font-bold block">
                    Mathematical Conclusion:
                  </span>
                  <div className="text-red-300 font-bold text-xs">
                    Vulnerability Formally Proved
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Zero probability of false alarm. The SMT solver verified real execution crash.
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-4 font-mono text-xs">
              <div className="p-4 rounded-xl bg-slate-950 border border-emerald-900/30 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-emerald-400 font-bold uppercase text-[11px]">
                    SMT-LIB2 Guarded Assertion Formula:
                  </span>
                  <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold text-[10px]">
                    Z3 VERDICT: UNSATISFIABLE (UNSAT)
                  </span>
                </div>
                <pre className="p-3 rounded-lg bg-black text-cyan-300 overflow-x-auto text-[11px] leading-relaxed">
{`; Sanitization Guard: Checked by compiler or explicit condition
(assert (bvule copy_size (_ bv8 64)))
; Safety Invariant Violation: attempt to prove out-of-bounds write
(assert (bvugt copy_size (_ bv8 64)))
; Theorem Prover Query:
(check-sat)`}
                </pre>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
                <span className="text-slate-400 text-[10px] uppercase font-bold block">
                  Formal Verification Guarantee:
                </span>
                <div className="text-emerald-300 font-bold text-xs">
                  Proved Clean (0 Vulnerabilities)
                </div>
                <div className="text-slate-400 text-[11px]">
                  The Z3 solver proved that no input can ever trigger a memory violation. Suppresses false positive completely.
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};
