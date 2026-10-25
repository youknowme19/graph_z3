import React, { useState } from 'react';
import {
  Network,
  Activity,
  Lock,
  ArrowRight,
  Terminal,
} from 'lucide-react';
import { BRAND } from '../config/brand';

interface ProductIntroSectionProps {
  onOpenWorkspace: () => void;
  onSelectSample?: (sampleId: string) => void;
}

export const ProductIntroSection: React.FC<ProductIntroSectionProps> = ({
  onOpenWorkspace,
}) => {
  const [activeTab, setActiveTab] = useState<'findings' | 'graph' | 'smt'>('findings');
  return (
    <section id="product" className="relative px-4 pt-10 pb-20 sm:px-6 lg:px-8">
      <div className="mx-auto max-w-7xl space-y-16">
        {/* Product Introduction Header */}
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-wider text-rose-500 font-semibold">
            <span className="h-2 w-2 rounded-full bg-rose-500 animate-pulse" />
            <span>OPERATIONAL WORKBENCH</span>
          </div>

          <h2 className="text-3xl font-extrabold tracking-tight sm:text-5xl text-primary">
            {BRAND.productIntroHeadline}
          </h2>

          <p className="text-base sm:text-lg text-secondary leading-relaxed">
            {BRAND.productIntroSubtext}
          </p>
        </div>

        {/* Desktop-Style Frame Preview with Real Functional Layout */}
        <div className="rounded-2xl border border-border bg-surface shadow-2xl overflow-hidden">
          {/* Frame Top Bar */}
          <div className="flex items-center justify-between border-b border-border bg-surface-raised/70 px-4 py-3">
            <div className="flex items-center gap-2">
              <span className="h-3 w-3 rounded-full bg-rose-500/80" />
              <span className="h-3 w-3 rounded-full bg-amber-500/80" />
              <span className="h-3 w-3 rounded-full bg-emerald-500/80" />
              <span className="ml-3 font-mono text-xs text-secondary font-semibold">
                {BRAND.name} OS — /app/workspace/target_analysis
              </span>
            </div>

            {/* View Selector */}
            <div className="flex items-center gap-1 rounded-lg border border-border bg-surface p-1 font-mono text-xs">
              <button
                type="button"
                onClick={() => setActiveTab('findings')}
                className={`rounded px-3 py-1 font-semibold transition-colors ${activeTab === 'findings'
                  ? 'bg-surface-raised text-rose-500 dark:text-rose-400 border border-border'
                  : 'text-secondary hover:text-primary'
                  }`}
              >
                Findings (1 Proved)
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('graph')}
                className={`rounded px-3 py-1 font-semibold transition-colors ${activeTab === 'graph'
                  ? 'bg-surface-raised text-emerald-600 dark:text-emerald-400 border border-border'
                  : 'text-secondary hover:text-primary'
                  }`}
              >
                VEX Control Flow
              </button>
              <button
                type="button"
                onClick={() => setActiveTab('smt')}
                className={`rounded px-3 py-1 font-semibold transition-colors ${activeTab === 'smt'
                  ? 'bg-surface-raised text-cyan-600 dark:text-cyan-400 border border-border'
                  : 'text-secondary hover:text-primary'
                  }`}
              >
                Z3 SMT Invariants
              </button>
            </div>
          </div>

          {/* Frame Interior Body */}
          <div className="p-6 bg-surface">
            {activeTab === 'findings' && (
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border pb-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-rose-500/10 text-rose-600 dark:text-rose-400 border border-rose-500/30 px-2 py-0.5 font-mono text-xs font-bold">
                        CRITICAL CVSS 7.9
                      </span>
                      <span className="font-semibold text-primary text-sm">
                        CWE-120: Classical Buffer Overflow (Stack Smash)
                      </span>
                    </div>
                    <p className="font-mono text-xs text-secondary">
                      Sink address: 0x10000051c · Instruction: strncpy_chk · Destination: 8 bytes
                    </p>
                  </div>

                  <button
                    type="button"
                    onClick={onOpenWorkspace}
                    className="btn-signal self-start sm:self-auto !text-xs !py-1.5"
                  >
                    <span>Launch In Workspace</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-3.5 rounded-lg bg-surface-raised border border-border space-y-1">
                    <span className="text-[10px] text-muted uppercase">GraphSAGE Risk</span>
                    <span className="text-rose-600 dark:text-rose-400 font-bold block text-sm">94.2% (Topological Priority)</span>
                    <span className="text-[10px] text-secondary">40-dim neighborhood embedding</span>
                  </div>
                  <div className="p-3.5 rounded-lg bg-surface-raised border border-border space-y-1">
                    <span className="text-[10px] text-muted uppercase">Z3 SMT Invariant</span>
                    <span className="text-emerald-600 dark:text-emerald-400 font-bold block text-sm">SATISFIABLE (3.1 ms)</span>
                    <span className="text-[10px] text-secondary">Zero false positive model</span>
                  </div>
                  <div className="p-3.5 rounded-lg bg-surface-raised border border-border space-y-1">
                    <span className="text-[10px] text-muted uppercase">Exploit Reproducer</span>
                    <span className="text-primary font-bold block text-sm">40 Concrete Bytes</span>
                    <span className="text-[10px] text-secondary">Deterministic payload harness</span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'graph' && (
              <div className="space-y-4">
                <div className="rounded-xl border border-border bg-surface-raised p-4 font-mono text-xs space-y-2">
                  <div className="flex justify-between items-center text-secondary border-b border-border pb-2">
                    <span>Target: cwe120_buffer_overflow.bin</span>
                    <span className="text-emerald-600 dark:text-emerald-400 font-semibold">31 Basic Blocks · 42 Edges</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 pt-2">
                    <div className="p-3 rounded bg-surface border border-emerald-500/30">
                      <span className="text-[10px] text-emerald-600 dark:text-emerald-400 font-bold block">0x1000004ac</span>
                      <span className="text-primary">main() entry block</span>
                    </div>
                    <div className="p-3 rounded bg-surface border border-amber-500/30">
                      <span className="text-[10px] text-amber-600 dark:text-amber-400 font-bold block">0x100000558</span>
                      <span className="text-primary">length guard conditional</span>
                    </div>
                    <div className="p-3 rounded bg-surface border border-rose-500/40">
                      <span className="text-[10px] text-rose-600 dark:text-rose-400 font-bold block">0x10000051c</span>
                      <span className="text-primary">memcpy_chk vulnerability sink</span>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'smt' && (
              <div className="space-y-3 font-mono text-xs">
                <div className="flex justify-between items-center text-secondary border-b border-border pb-2">
                  <span>SMT-LIB2 Bitvector Formulation (Theory of Arrays & Bitvectors)</span>
                  <span className="text-rose-600 dark:text-rose-400 font-bold">Z3 Verified SAT</span>
                </div>
                <pre className="p-3 rounded-lg bg-surface-raised text-rose-600 dark:text-rose-400 leading-relaxed overflow-x-auto border border-border">
                  {`; Concrete path predicates extracted by angr
(declare-const packet_len (_ BitVec 64))
(declare-const copy_size (_ BitVec 64))
(assert (bvuge packet_len (_ bv64 64)))
(assert (bvugt copy_size (_ bv8 64)))
(check-sat)
; -> sat
; Synthesized counterexample: [32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, ...]`}
                </pre>
              </div>
            )}
          </div>
        </div>

        {/* Minimal Feature Presentation (4 Pillars) */}
        <div className="space-y-6 pt-8">
          <div className="max-w-2xl">
            <span className="font-mono text-xs uppercase tracking-wider text-rose-500 font-semibold">
              CORE CAPABILITIES
            </span>
            <h3 className="text-2xl font-bold text-primary sm:text-3xl mt-1">
              Architected for Mathematical Precision
            </h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Feature 1 */}
            <div className="card-vanta-interactive p-6 space-y-3">
              <div className="h-10 w-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                <Network className="h-5 w-5" />
              </div>
              <h4 className="font-semibold text-primary text-base">Graph Intelligence</h4>
              <p className="text-xs text-secondary leading-relaxed">
                Recovers control flow into attributed VEX IR graphs. Embeds basic blocks with 40-dimensional GraphSAGE features before symbolic exploration.
              </p>
            </div>

            {/* Feature 2 */}
            <div className="card-vanta-interactive p-6 space-y-3">
              <div className="h-10 w-10 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400">
                <Lock className="h-5 w-5" />
              </div>
              <h4 className="font-semibold text-primary text-base">Symbolic Reasoning</h4>
              <p className="text-xs text-secondary leading-relaxed">
                Formal theorem proving powered by Z3. Evaluates boundary constraints to emit zero false-positive results on proved execution paths.
              </p>
            </div>

            {/* Feature 3 */}
            <div className="card-vanta-interactive p-6 space-y-3">
              <div className="h-10 w-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                <Activity className="h-5 w-5" />
              </div>
              <h4 className="font-semibold text-primary text-base">Risk-Prioritized Triage</h4>
              <p className="text-xs text-secondary leading-relaxed">
                Prunes 99.66% of benign branches, avoiding the classic path explosion problem that paralyses traditional symbolic tools.
              </p>
            </div>

            {/* Feature 4 */}
            <div className="card-vanta-interactive p-6 space-y-3">
              <div className="h-10 w-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-400">
                <Terminal className="h-5 w-5" />
              </div>
              <h4 className="font-semibold text-primary text-base">Developer-First Output</h4>
              <p className="text-xs text-secondary leading-relaxed">
                Direct export to OASIS SARIF 2.1.0 for CI/CD, accompanied by concrete byte reproducers and compiler mitigation diffs.
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
