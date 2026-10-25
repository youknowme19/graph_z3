import React from 'react';
import { Shield, FileCheck, Lock, Activity } from 'lucide-react';

const ITEMS = [
  {
    icon: FileCheck,
    title: 'OASIS SARIF 2.1.0 Export',
    desc: 'Native ingestion for GitHub Advanced Security, GitLab Ultimate, DefectDojo, and enterprise AppSec pipelines.',
  },
  {
    icon: Shield,
    title: 'Formal Invariant Coverage',
    desc: 'CWE-120, 121, 134, 416, 476, and 078 modeled directly as mathematical bitvector SMT assertions.',
  },
  {
    icon: Lock,
    title: 'Air-Gapped & Isolated',
    desc: 'Local execution sends zero telemetry. Verification executes strictly on premises or in your sovereign cloud.',
  },
  {
    icon: Activity,
    title: 'Automated CVSS v3.1',
    desc: 'Composite and peak severity scoring generated deterministically from verified counterexample primitives.',
  },
];

export const SecurityAuditorsBadge: React.FC = () => {
  return (
    <section className="relative px-4 py-16 sm:px-6 lg:px-8 border-t border-border">
      <div className="mx-auto max-w-7xl space-y-6">
        <div>
          <span className="font-mono text-xs uppercase tracking-wider text-rose-500 font-semibold">
            Enterprise & DevSecOps
          </span>
          <h2 className="text-2xl font-bold tracking-tight text-primary sm:text-3xl mt-1">
            Production-Ready Security Integrations
          </h2>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {ITEMS.map((item) => {
            const Icon = item.icon;
            return (
              <div
                key={item.title}
                className="rounded-xl border border-border bg-surface p-5 space-y-3 transition-colors hover:border-rose-500/40"
              >
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-surface-raised border border-border text-rose-500">
                  <Icon className="h-4 w-4" />
                </div>
                <h3 className="font-semibold text-sm text-primary">{item.title}</h3>
                <p className="text-xs text-secondary leading-relaxed">{item.desc}</p>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};
