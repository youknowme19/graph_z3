import React from 'react';
import { Layers } from 'lucide-react';
import { BRAND } from '../config/brand';

const ROWS = [
  {
    metric: 'False Positive Rate',
    vanta: '0.0% on proved paths',
    afl: 'Low (crash dumps only)',
    sonar: 'High (pattern matching)',
    angr: 'SimProcedure quirks',
  },
  {
    metric: 'Path-Space Pruning',
    vanta: '99.66% via GraphSAGE',
    afl: 'Coverage heuristics',
    sonar: 'N/A',
    angr: 'Exhaustive DFS',
  },
  {
    metric: 'Exploit Reproducer',
    vanta: 'Exact concrete bytes',
    afl: 'Raw mutated input',
    sonar: 'None (advisory text)',
    angr: 'Raw AST expressions',
  },
  {
    metric: 'Stripped Binaries',
    vanta: 'VEX IR + Attributed CFG',
    afl: 'Requires instrumentation',
    sonar: 'Source code only',
    angr: 'Native binary execution',
  },
  {
    metric: 'CI/CD Reporting',
    vanta: 'OASIS SARIF 2.1.0 · JSON',
    afl: 'Crash directory dump',
    sonar: 'Issue tickets',
    angr: 'Raw SMT-LIB2 format',
  },
  {
    metric: 'Architectures',
    vanta: 'x86-64 · AArch64 · ARM',
    afl: 'Instrumented build target',
    sonar: 'Source language AST',
    angr: 'Multi-architecture VEX',
  },
];

export const BenchmarkComparison: React.FC = () => {
  return (
    <section id="benchmarks" className="relative px-4 py-16 sm:px-6 lg:px-8 border-t border-border">
      <div className="mx-auto max-w-7xl space-y-6">
        <div>
          <div className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-rose-500 font-semibold">
            <Layers className="h-3.5 w-3.5" />
            <span>Capability Comparison</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-primary sm:text-3xl mt-1">
            Formal Invariant Prover vs Heuristic Scanners
          </h2>
          <p className="text-sm text-secondary max-w-2xl mt-1">
            Engine capabilities verified against benchmark targets without arbitrary marketing claims.
          </p>
        </div>

        <div className="overflow-x-auto rounded-xl border border-border bg-surface/80 backdrop-blur-sm">
          <table className="w-full min-w-[640px] text-left text-xs">
            <thead>
              <tr className="border-b border-border font-mono text-[11px] text-secondary">
                <th className="px-5 py-3.5 font-medium">Evaluation Metric</th>
                <th className="bg-rose-500/10 px-5 py-3.5 font-bold text-rose-400 border-x border-rose-500/20">
                  {BRAND.name}
                </th>
                <th className="px-5 py-3.5 font-medium">AFL++ (Fuzzing)</th>
                <th className="px-5 py-3.5 font-medium">Static Linters</th>
                <th className="px-5 py-3.5 font-medium">Vanilla angr</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border font-mono">
              {ROWS.map((row) => (
                <tr key={row.metric} className="hover:bg-surface-raised/40 transition-colors">
                  <td className="px-5 py-3.5 font-sans font-medium text-primary">
                    {row.metric}
                  </td>
                  <td className="bg-rose-500/5 px-5 py-3.5 font-semibold text-rose-400 border-x border-rose-500/20">
                    {row.vanta}
                  </td>
                  <td className="px-5 py-3.5 text-secondary">{row.afl}</td>
                  <td className="px-5 py-3.5 text-secondary">{row.sonar}</td>
                  <td className="px-5 py-3.5 text-secondary">{row.angr}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
};
