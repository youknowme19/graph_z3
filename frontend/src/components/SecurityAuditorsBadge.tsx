import React from 'react';
import { ShieldCheck, FileCheck, Award, Lock } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const SecurityAuditorsBadge: React.FC = () => {
  const complianceItems = [
    {
      title: 'OASIS SARIF 2.1.0',
      desc: 'Native JSON export for GitHub Advanced Security code scanning alerts and CI/CD pipelines.',
      icon: <FileCheck className="w-5 h-5 text-cyan-400" />,
    },
    {
      title: 'CWE/SANS Top 25',
      desc: 'Formal verification covering memory safety, buffer boundaries, UAF, and command injection.',
      icon: <ShieldCheck className="w-5 h-5 text-emerald-400" />,
    },
    {
      title: 'Air-Gapped & Offline',
      desc: '100% on-premise execution. No binary telemetry or payloads ever leave your host.',
      icon: <Lock className="w-5 h-5 text-purple-400" />,
    },
    {
      title: 'CVSS v3.1 Scoring',
      desc: 'Automated CVSS severity computation with composite average and peak risk gauge metrics.',
      icon: <Award className="w-5 h-5 text-amber-400" />,
    },
  ];

  return (
    <section className="relative py-16 space-y-12">
      <div className="flex justify-center">
        <HoloSticker
          label="DEVSECOPS READY // ENTERPRISE ASSURANCE"
          sublabel="Built for mission-critical security pipelines"
          variant="secure"
          rotation={1}
          floatAnimation="gentle"
          icon={<ShieldCheck className="w-4 h-4 text-emerald-300" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          Built for High-Stakes{' '}
          <span className="bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
            Security Audits
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Whether you are hardening firmware, auditing proprietary libraries, or securing aerospace microkernels, GRAPH_Z3 provides verifiable mathematical assurance.
        </p>
      </div>

      {/* Compliance Grid */}
      <div className="max-w-5xl mx-auto px-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {complianceItems.map((item, idx) => (
            <div
              key={idx}
              className="metamask-card rounded-2xl p-5 space-y-3 font-mono text-xs"
            >
              <div className="w-10 h-10 rounded-xl bg-slate-900/80 border border-slate-700/60 flex items-center justify-center">
                {item.icon}
              </div>
              <div className="text-sm font-bold text-slate-200">{item.title}</div>
              <p className="text-slate-400 text-[11px] leading-relaxed font-sans">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};
