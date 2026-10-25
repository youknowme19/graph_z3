import React, { useState } from 'react';

const STAGES = [
  {
    id: 'ingest',
    n: '00',
    title: 'Lift',
    body: 'ELF, PE, and Mach-O binaries are loaded, mitigations (ASLR, DEP, canaries, RELRO) recorded, and disassembly translated to VEX IR for a recovered CFG.',
  },
  {
    id: 'gnn',
    n: '01',
    title: 'Rank',
    body: 'A 2-layer GraphSAGE network embeds each basic block as a 40-dimensional feature vector and scores exploitability, pruning more than 99% of the search space.',
  },
  {
    id: 'smt',
    n: '02',
    title: 'Prove',
    body: 'High-risk paths enter bounded angr symbolic execution. Path predicates and exploit conditions are handed to Z3. UNSAT discards the path. SAT is a proof.',
  },
  {
    id: 'out',
    n: '03',
    title: 'Emit',
    body: 'Satisfiable models become concrete crash payloads, SARIF 2.1.0 artifacts, JSON diagnostics, and a CFG workbench — not a heap of heuristic alerts.',
  },
];

export const EngineStrip: React.FC = () => {
  const [active, setActive] = useState(1);
  const stage = STAGES[active];

  return (
    <section id="act-engine" className="relative px-4 py-20 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl">
        <div className="grid gap-10 lg:grid-cols-12">
          <div className="lg:col-span-4">
            <p className="kicker">Act III · Dual-stage engine</p>
            <h2 className="display mt-4 text-4xl sm:text-5xl lg:text-6xl">
              Inductive ranking, then a theorem.
            </h2>
            <p className="mt-5 text-sm leading-relaxed text-paper-dim sm:text-base">
              GRAPH_Z3 does not guess with mutations and does not trust syntax alarms. It
              first learns which blocks are worth asking about, then demands a satisfying
              assignment from Z3.
            </p>
          </div>

          <div className="lg:col-span-8">
            <ol className="grid grid-cols-2 gap-px border border-line bg-line sm:grid-cols-4">
              {STAGES.map((s, i) => (
                <li key={s.id}>
                  <button
                    type="button"
                    onClick={() => setActive(i)}
                    className={`flex h-full w-full flex-col items-start bg-ink px-4 py-5 text-left transition-colors ${
                      active === i ? 'bg-ink-3' : 'hover:bg-ink-2'
                    }`}
                  >
                    <span className="font-mono text-[10px] text-mute">{s.n}</span>
                    <span className={`mt-2 font-display text-2xl ${active === i ? 'text-signal' : 'text-paper'}`}>
                      {s.title}
                    </span>
                  </button>
                </li>
              ))}
            </ol>
            <div className="border border-t-0 border-line bg-ink-2 p-6 sm:p-8">
              <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-brass">
                Stage {stage.n} · {stage.title}
              </p>
              <p className="mt-3 max-w-2xl text-sm leading-relaxed text-paper-dim sm:text-base">
                {stage.body}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
