import React from 'react';
import { TerminalSquare, ArrowRight, ShieldAlert, Zap, Cpu, Code2 } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const StoryChapter3: React.FC = () => {
  const attackSteps = [
    {
      num: '01',
      title: 'Taint Ingestion',
      desc: 'User payload bytes marked symbolic at standard input or network buffer.',
      badge: 'BVS 40-Byte Vector',
      badgeColor: 'text-cyan-400 border-cyan-800 bg-cyan-950/60',
    },
    {
      num: '02',
      title: 'Graph Traversal',
      desc: 'SageConv GNN steers execution path toward unvalidated copy sink in _main.',
      badge: 'Path Risk: 94.2%',
      badgeColor: 'text-purple-400 border-purple-800 bg-purple-950/60',
    },
    {
      num: '03',
      title: 'Constraint Breach',
      desc: 'Destination buffer (8B) breached. Stack frame saved x30 register reached.',
      badge: 'STACK_SMASH_RIP',
      badgeColor: 'text-red-400 border-red-800 bg-red-950/60',
    },
    {
      num: '04',
      title: 'SMT Solving',
      desc: 'Z3 generates concrete satisfying model satisfying all branch conditions.',
      badge: 'Z3 SAT (3.2 ms)',
      badgeColor: 'text-emerald-400 border-emerald-800 bg-emerald-950/60',
    },
    {
      num: '05',
      title: 'Reproducer Generation',
      desc: 'Synthesizes clean decimal byte array and executable 1-line Python command.',
      badge: 'Executable PoC',
      badgeColor: 'text-amber-400 border-amber-800 bg-amber-950/60',
    },
  ];

  return (
    <section className="relative py-16 space-y-12">
      <div className="flex justify-center">
        <HoloSticker
          label="ACT IV // EXPLOIT PRIMITIVE SYNTHESIS"
          sublabel="From Mathematical Proof to 100% Working PoC"
          variant="hazard"
          rotation={2}
          floatAnimation="tilt"
          icon={<Zap className="w-4 h-4 text-slate-950" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          From Abstract Vulnerability to{' '}
          <span className="bg-gradient-to-r from-amber-400 via-orange-400 to-red-400 bg-clip-text text-transparent">
            Concrete Reproducer
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          GRAPH_Z3 doesn't stop at theoretical warnings. It delivers an end-to-end exploit attack chain and a clean, copy-pasteable Python CLI command that proves the vulnerability in your local terminal.
        </p>
      </div>

      {/* 5-Stage Exploit Attack Chain Grid */}
      <div className="max-w-5xl mx-auto px-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
          {attackSteps.map((step) => (
            <div
              key={step.num}
              className="metamask-card rounded-2xl p-5 space-y-3 relative group"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono font-black text-lg text-slate-500 group-hover:text-cyan-400 transition-colors">
                  {step.num}
                </span>
                <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border ${step.badgeColor}`}>
                  {step.badge}
                </span>
              </div>
              <div className="font-mono text-xs font-bold text-slate-200">
                {step.title}
              </div>
              <p className="text-slate-400 text-[11px] leading-relaxed">
                {step.desc}
              </p>
            </div>
          ))}
        </div>

        {/* Reproducer Terminal Showcase */}
        <div className="mt-8 metamask-card rounded-3xl p-6 sm:p-8 space-y-4 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div className="flex items-center gap-2 text-slate-300 font-bold">
              <TerminalSquare className="w-4 h-4 text-cyan-400" />
              <span>LIVE EXPLOIT REPRODUCER ARTIFACT</span>
            </div>
            <span className="text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/60 text-[10px] font-bold">
              SMT-SOLVED BREAKING POINT
            </span>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
            <span className="text-[10px] text-slate-500 uppercase tracking-wider block">
              Z3 Solved Byte Numbers (Decimal Array):
            </span>
            <div className="text-amber-300 font-mono text-xs break-all leading-relaxed select-all">
              [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, 32, 32, 2, 8, 32, 2, 4, 128, 2, 64, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15]
            </div>
          </div>

          <pre className="p-4 rounded-xl bg-black border border-slate-800 text-cyan-300 font-mono text-xs overflow-x-auto select-all">
            python3 -c "import sys; sys.stdout.buffer.write(bytes([32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, 32, 32, 2, 8, 32, 2, 4, 128, 2, 64, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15]))" | ./cwe120_buffer_overflow.bin
          </pre>
        </div>
      </div>
    </section>
  );
};
