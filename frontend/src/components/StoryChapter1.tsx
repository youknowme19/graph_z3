import React, { useEffect, useRef, useState } from 'react';
import { StoryPin } from './StoryPin';
import { sectionProgress } from '../lib/motion';

const NODES = [
  { id: 0, addr: '0x1000004ac', name: 'main prologue', type: 'Entry block', score: 0.12, status: 'Benign' },
  { id: 1, addr: '0x10000051c', name: 'bounded copy sink', type: 'Vulnerability sink', score: 0.94, status: 'Critical risk' },
  { id: 2, addr: '0x100000558', name: 'length validator', type: 'Branch guard', score: 0.47, status: 'Medium risk' },
  { id: 3, addr: '0x100000580', name: 'epilogue return', type: 'Exit block', score: 0.08, status: 'Normal' },
];

const VECTORS: Record<number, number[]> = {
  0: [0.12, 0.08, 0.15, 0.1, 0.09, 0.13, 0.07, 0.11, 0.14, 0.06, 0.1, 0.08, 0.12, 0.09, 0.11, 0.07],
  1: [0.94, 0.88, 0.91, 0.76, 0.83, 0.9, 0.87, 0.72, 0.95, 0.68, 0.79, 0.85, 0.92, 0.77, 0.88, 0.94],
  2: [0.47, 0.42, 0.51, 0.38, 0.44, 0.49, 0.36, 0.52, 0.41, 0.47, 0.43, 0.5, 0.39, 0.48, 0.45, 0.53],
  3: [0.08, 0.1, 0.09, 0.11, 0.07, 0.12, 0.06, 0.09, 0.08, 0.1, 0.07, 0.11, 0.09, 0.08, 0.1, 0.06],
};

export const StoryChapter1: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [activeNode, setActiveNode] = useState(1);

  useEffect(() => {
    const onScroll = () => {
      const p = sectionProgress(sectionRef.current);
      setActiveNode(Math.min(3, Math.floor(p * 4.2)));
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const node = NODES[activeNode];
  const vector = VECTORS[activeNode];

  return (
    <div id="act-cfg" ref={sectionRef}>
      <StoryPin>
        <div className="flex h-full flex-col overflow-auto px-4 py-10 sm:px-6 lg:px-8">
          <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6">
            <div>
              <p className="kicker">Act IV · GraphSAGE on the CFG</p>
              <h2 className="display mt-3 max-w-3xl text-4xl sm:text-5xl">
                Every block gets a 40-dim opinion before angr moves.
              </h2>
            </div>

            <div className="grid flex-1 gap-4 lg:grid-cols-5">
              <div className="flex flex-col gap-2 lg:col-span-2">
                {NODES.map((n) => (
                  <button
                    key={n.id}
                    type="button"
                    onClick={() => setActiveNode(n.id)}
                    className={`border px-4 py-3 text-left transition-colors ${
                      activeNode === n.id ? 'border-signal bg-ink-3' : 'border-line bg-ink-2 hover:border-line-strong'
                    }`}
                  >
                    <div className="flex items-center justify-between font-mono text-[10px] uppercase tracking-[0.14em] text-mute">
                      <span>Block {n.id}</span>
                      <span className={n.score > 0.8 ? 'text-hazard' : 'text-brass'}>
                        {(n.score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div className="mt-1 font-mono text-xs text-paper">{n.addr}</div>
                    <div className="text-xs text-mute">{n.name}</div>
                  </button>
                ))}
              </div>

              <div className="border border-line bg-ink-2 p-5 lg:col-span-3">
                <div className="flex items-start justify-between gap-3 border-b border-line pb-3">
                  <div>
                    <div className="font-mono text-xs text-signal">
                      {node.addr} · {node.name}
                    </div>
                    <div className="mt-1 text-xs text-mute">{node.type}</div>
                  </div>
                  <span className="font-mono text-[10px] uppercase tracking-[0.14em] text-brass">
                    {node.status}
                  </span>
                </div>

                <div className="mt-5">
                  <div className="flex justify-between font-mono text-[10px] uppercase tracking-[0.14em]">
                    <span className="text-mute">SageConv score</span>
                    <span className={node.score > 0.8 ? 'text-hazard' : 'text-signal'}>
                      {(node.score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="mt-2 h-1.5 bg-ink-3">
                    <div
                      className="h-full bg-signal"
                      style={{
                        width: `${node.score * 100}%`,
                        background: node.score > 0.8 ? 'var(--color-hazard)' : 'var(--color-signal)',
                      }}
                    />
                  </div>
                </div>

                <p className="mt-5 font-mono text-[10px] uppercase tracking-[0.14em] text-mute">
                  Sampled feature vector
                </p>
                <div className="mt-2 grid grid-cols-8 gap-1">
                  {vector.map((v, i) => (
                    <div
                      key={i}
                      title={`dim ${i}: ${v.toFixed(2)}`}
                      className="flex aspect-square items-center justify-center font-mono text-[9px]"
                      style={{
                        background: `rgba(212, 255, 74, ${0.08 + v * 0.7})`,
                        color: v > 0.55 ? '#14180a' : '#c9c2b4',
                      }}
                    >
                      {v.toFixed(1)}
                    </div>
                  ))}
                </div>

                <div className="mt-5 border border-line bg-ink p-4 font-mono text-xs leading-relaxed text-paper-dim">
                  {node.id === 1
                    ? 'High-priority sink: angr starts a directed symbolic slice with tainted stdin. Z3 will decide reachability.'
                    : node.id === 2
                      ? 'Guard branch: both outcomes are checked against the safety invariant. Contradiction means UNSAT.'
                      : 'Low priority: cached SimProcedures skip constraint solving for this block.'}
                </div>
              </div>
            </div>
          </div>
        </div>
      </StoryPin>
    </div>
  );
};
