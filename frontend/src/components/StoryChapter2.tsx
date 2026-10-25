import React, { useEffect, useRef, useState } from 'react';
import { Lock, Unlock } from 'lucide-react';
import { StoryPin } from './StoryPin';
import { sectionProgress } from '../lib/motion';

const PROOFS = [
  {
    key: 'stack_overflow',
    label: 'Vulnerable path',
    verdict: 'SAT',
    formula: `; Path: user length reaches copy sink
(assert (bvuge packet_len (_ bv64 64)))
; Write exceeds 8-byte stack buffer
(assert (bvugt copy_size (_ bv8 64)))
(check-sat)
; → sat
; packet_len = 64, copy_size = 72`,
    result: 'Vulnerability formally proved',
    resultDesc:
      'Z3 synthesizes a 40-byte model. The stack frame is overwritten at byte 32; the return address is hijacked. This is a counterexample, not an alert.',
  },
  {
    key: 'secure_invariant',
    label: 'Guarded path',
    verdict: 'UNSAT',
    formula: `; Guard already bounds the copy
(assert (bvule copy_size (_ bv8 64)))
; Simultaneous OOB write
(assert (bvugt copy_size (_ bv8 64)))
(check-sat)
; → unsat
; No model — contradiction.`,
    result: 'Memory safety proved',
    resultDesc:
      'The two assertions cannot hold together. No crash payload exists on this path, so GRAPH_Z3 emits zero findings.',
  },
] as const;

const STEPS = ['Parse', 'Constraint graph', 'DPLL(T)', 'Model', 'Payload', 'Report'];

export const StoryChapter2: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [selected, setSelected] = useState<(typeof PROOFS)[number]['key']>('stack_overflow');
  const [animStep, setAnimStep] = useState(0);

  useEffect(() => {
    const onScroll = () => {
      const p = sectionProgress(sectionRef.current);
      setAnimStep(Math.floor(p * 6));
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const proof = PROOFS.find((p) => p.key === selected)!;
  const sat = selected === 'stack_overflow';

  return (
    <div id="act-smt" ref={sectionRef}>
      <StoryPin>
        <div className="flex h-full flex-col overflow-auto px-4 py-10 sm:px-6 lg:px-8">
          <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6">
            <div>
              <p className="kicker">Act V · Z3 SMT</p>
              <h2 className="display mt-3 max-w-3xl text-4xl sm:text-5xl">
                SAT is a proof. UNSAT is silence.
              </h2>
            </div>

            <div className="flex gap-px border border-line bg-line self-start">
              {PROOFS.map((p) => (
                <button
                  key={p.key}
                  type="button"
                  onClick={() => setSelected(p.key)}
                  className={`flex items-center gap-2 bg-ink px-4 py-2 font-mono text-[11px] uppercase tracking-[0.14em] ${
                    selected === p.key ? (p.key === 'stack_overflow' ? 'text-hazard' : 'text-safe') : 'text-mute'
                  }`}
                >
                  {p.key === 'stack_overflow' ? <Unlock className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
                  {p.label}
                </button>
              ))}
            </div>

            <div className="grid flex-1 gap-4 md:grid-cols-2">
              <div className="border border-line bg-ink-2 p-5">
                <div className="flex items-center justify-between border-b border-line pb-3 font-mono text-[11px] uppercase tracking-[0.14em]">
                  <span className="text-mute">SMT-LIB2</span>
                  <span className={sat ? 'text-hazard' : 'text-safe'}>Z3 · {proof.verdict}</span>
                </div>
                <pre className="mt-4 overflow-x-auto font-mono text-[11px] leading-relaxed text-brass">
                  {proof.formula}
                </pre>
                <div className="mt-5 grid grid-cols-3 gap-1">
                  {STEPS.map((step, i) => (
                    <div
                      key={step}
                      className={`px-2 py-2 text-center font-mono text-[9px] uppercase tracking-[0.12em] ${
                        i <= animStep ? 'bg-signal/15 text-signal' : 'bg-ink text-mute'
                      }`}
                    >
                      {step}
                    </div>
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <div className="border border-line bg-ink-2 p-5">
                  <p className={`font-display text-3xl ${sat ? 'text-hazard' : 'text-safe'}`}>
                    {proof.result}
                  </p>
                  <p className="mt-3 text-sm leading-relaxed text-paper-dim">{proof.resultDesc}</p>
                </div>
                {sat && (
                  <div className="border border-line bg-ink p-5">
                    <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-signal">
                      Concrete model
                    </p>
                    <p className="mt-3 break-all font-mono text-xs text-paper">
                      [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, …]
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </StoryPin>
    </div>
  );
};
