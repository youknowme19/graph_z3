import React, { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { StoryPin } from './StoryPin';
import { sectionProgress } from '../lib/motion';

const ATTACK_STEPS = [
  { num: '01', title: 'Taint ingestion', desc: 'Stdin bytes marked symbolic at the buffer entry point.', badge: 'BVS 40-byte' },
  { num: '02', title: 'Graph traversal', desc: 'SageConv steers angr toward the unvalidated copy sink.', badge: 'Risk 94.2%' },
  { num: '03', title: 'Constraint breach', desc: '8-byte destination exceeded. Saved return register overwritten.', badge: 'STACK_SMASH' },
  { num: '04', title: 'Z3 SMT solve', desc: 'Z3 returns a model that satisfies every path predicate.', badge: 'SAT 3.2 ms' },
  { num: '05', title: 'PoC emission', desc: 'Decimal byte array plus a one-line Python reproducer.', badge: 'Executable' },
];

const PAYLOAD = [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, 32, 32, 2, 8, 32, 2, 4, 128, 2, 64, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15];

export const StoryChapter3: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [activeStep, setActiveStep] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    const onScroll = () => {
      const p = sectionProgress(sectionRef.current);
      setActiveStep(Math.min(4, Math.floor(p * 5.2)));
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const handleCopy = () => {
    const cmd = `python3 -c "import sys; sys.stdout.buffer.write(bytes([${PAYLOAD.join(', ')}]))" | ./cwe120_buffer_overflow.bin`;
    navigator.clipboard.writeText(cmd);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const step = ATTACK_STEPS[activeStep];

  return (
    <div id="act-payload" ref={sectionRef}>
      <StoryPin>
        <div className="flex h-full flex-col overflow-auto px-4 py-10 sm:px-6 lg:px-8">
          <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6">
            <div>
              <p className="kicker">Act VI · Payload synthesis</p>
              <h2 className="display mt-3 max-w-3xl text-4xl sm:text-5xl">
                From a satisfying assignment to a reproducer.
              </h2>
            </div>

            <div className="grid flex-1 gap-4 lg:grid-cols-5">
              <div className="flex flex-col gap-2 lg:col-span-2">
                {ATTACK_STEPS.map((s, i) => (
                  <button
                    key={s.num}
                    type="button"
                    onClick={() => setActiveStep(i)}
                    className={`border px-4 py-3 text-left ${
                      activeStep === i ? 'border-signal bg-ink-3' : 'border-line bg-ink-2 hover:border-line-strong'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-display text-2xl text-signal">{s.num}</span>
                      <span className="font-mono text-[10px] uppercase tracking-[0.12em] text-brass">{s.badge}</span>
                    </div>
                    <div className="mt-1 text-sm text-paper">{s.title}</div>
                    <p className="mt-1 text-xs text-mute">{s.desc}</p>
                  </button>
                ))}
              </div>

              <div className="flex flex-col gap-4 lg:col-span-3">
                <div className="border border-line bg-ink-2 p-5">
                  <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-mute">
                    Stage {step.num} of 05
                  </p>
                  <h3 className="display mt-2 text-3xl">{step.title}</h3>
                  <p className="mt-2 text-sm text-paper-dim">{step.desc}</p>
                  <div className="mt-4 h-1 bg-ink-3">
                    <div
                      className="h-full bg-signal"
                      style={{ width: `${((activeStep + 1) / 5) * 100}%` }}
                    />
                  </div>
                </div>

                <div className="flex-1 border border-line bg-ink p-5">
                  <div className="flex items-center justify-between">
                    <p className="font-mono text-[10px] uppercase tracking-[0.16em] text-signal">
                      Z3 decimal model
                    </p>
                    <button
                      type="button"
                      onClick={handleCopy}
                      className="btn-ghost !px-2 !py-1"
                      aria-label="Copy reproducer"
                    >
                      {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                    </button>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-1">
                    {PAYLOAD.map((byte, i) => (
                      <span
                        key={i}
                        className="flex h-8 w-8 items-center justify-center font-mono text-[9px]"
                        style={{
                          background: `rgba(212, 255, 74, ${0.05 + (byte / 255) * 0.55})`,
                          color: byte > 64 ? '#14180a' : '#c9c2b4',
                          opacity: activeStep >= 3 ? 1 : 0.35,
                        }}
                        title={`byte ${i}: ${byte}`}
                      >
                        {byte}
                      </span>
                    ))}
                  </div>
                  <pre className="mt-4 overflow-x-auto font-mono text-[10px] leading-relaxed text-brass">
                    {`python3 -c "import sys; sys.stdout.buffer.write(bytes([${PAYLOAD.join(', ')}]))" | ./cwe120_buffer_overflow.bin`}
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </div>
      </StoryPin>
    </div>
  );
};
