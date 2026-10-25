import React, { useEffect, useRef, useState } from 'react';
import { StoryPin } from './StoryPin';
import { sectionProgress } from '../lib/motion';

export const StoryPrologue: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [progress, setProgress] = useState(0);
  const [mode, setMode] = useState<'legacy' | 'graph'>('legacy');

  useEffect(() => {
    const onScroll = () => {
      const p = sectionProgress(sectionRef.current);
      setProgress(p);
      setMode(p >= 0.48 ? 'graph' : 'legacy');
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const legacyOn = mode === 'legacy';

  return (
    <div id="act-crisis" ref={sectionRef}>
      <StoryPin>
        <div className="flex h-full flex-col px-4 py-10 sm:px-6 lg:px-8">
          <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col">
            <p className="kicker">Act II · Path explosion</p>
            <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
              <h2 className="display max-w-3xl text-4xl sm:text-5xl lg:text-6xl">
                Fifty branches is already a{' '}
                <em className="text-hazard">quadrillion</em> paths.
              </h2>
              <p className="max-w-md text-sm leading-relaxed text-paper-dim">
                AFL++ bit-flips hoping to satisfy a magic constant. Static linters flag every{' '}
                <code>strcpy</code>. GRAPH_Z3 refuses that trade: prune first, prove second.
              </p>
            </div>

            <div className="mt-8 flex items-center gap-4 font-mono text-[10px] uppercase tracking-[0.16em]">
              <button
                type="button"
                onClick={() => setMode('legacy')}
                className={legacyOn ? 'text-hazard' : 'text-mute'}
              >
                Legacy
              </button>
              <div className="h-px flex-1 bg-line">
                <div
                  className="h-px bg-signal"
                  style={{ width: `${Math.round(progress * 100)}%` }}
                />
              </div>
              <button
                type="button"
                onClick={() => setMode('graph')}
                className={!legacyOn ? 'text-signal' : 'text-mute'}
              >
                GRAPH_Z3
              </button>
            </div>

            <div className="mt-6 grid flex-1 gap-4 md:grid-cols-2">
              <article
                className={`border border-line bg-ink-2 p-6 transition-opacity ${legacyOn ? 'opacity-100' : 'opacity-40'}`}
              >
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-hazard">
                  AFL++ · linters · unguided SE
                </p>
                <ul className="mt-5 space-y-5 text-sm text-paper-dim">
                  <li>
                    <strong className="block font-sans text-paper">Path explosion</strong>
                    50 conditionals → 2<sup>50</sup> branches. Mutation fuzzers wait hours or never
                    hit <code className="text-brass">magic == 0x5a31</code>.
                  </li>
                  <li>
                    <strong className="block font-sans text-paper">Syntax false positives</strong>
                    Pattern matchers alarm on bounded copies. Noise, not proofs.
                  </li>
                  <li>
                    <strong className="block font-sans text-paper">Opaque crashes</strong>
                    When a fuzzer hits something, the dump is not a minimal, reasoned input.
                  </li>
                </ul>
              </article>

              <article
                className={`border border-line bg-ink-2 p-6 transition-opacity ${!legacyOn ? 'opacity-100' : 'opacity-40'}`}
              >
                <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-signal">
                  GraphSAGE · angr · Z3
                </p>
                <ul className="mt-5 space-y-5 text-sm text-paper-dim">
                  <li>
                    <strong className="block font-sans text-paper">GNN-guided steering</strong>
                    40-dim SageConv scores prune 99.66% of benign blocks before symbolic search.
                  </li>
                  <li>
                    <strong className="block font-sans text-paper">Z3 invariant proofs</strong>
                    UNSAT emits nothing. SAT is a counterexample, not a heuristic hit.
                  </li>
                  <li>
                    <strong className="block font-sans text-paper">Concrete payloads</strong>
                    The model is a byte array and a one-line reproducer — from the solver, not a blob.
                  </li>
                </ul>
              </article>
            </div>
          </div>
        </div>
      </StoryPin>
    </div>
  );
};
