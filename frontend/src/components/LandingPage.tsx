import React from 'react';
import { HeroSection } from './HeroSection';
import { StoryPrologue } from './StoryPrologue';
import { StoryChapter1 } from './StoryChapter1';
import { StoryChapter2 } from './StoryChapter2';
import { StoryChapter3 } from './StoryChapter3';
import { StoryChapter4 } from './StoryChapter4';
import { BenchmarkComparison } from './BenchmarkComparison';
import { InteractiveTerminal } from './InteractiveTerminal';
import { InteractiveSandbox } from './InteractiveSandbox';
import { SecurityAuditorsBadge } from './SecurityAuditorsBadge';
import { CyberFooter } from './CyberFooter';
import type { SampleBinary } from '../types';

interface LandingPageProps {
  onStartIntake: () => void;
  onSelectSample: (sampleId: string) => void;
  samples: SampleBinary[];
}

/** Glowing gradient divider between sections (MetaMask-style) */
const SectionDivider: React.FC<{ glow?: string }> = ({ glow = 'rgba(56,189,248,0.4)' }) => (
  <div className="py-1 px-6">
    <div className="relative h-px mx-auto" style={{ maxWidth: '800px' }}>
      <div className="absolute inset-0" style={{
        background: `linear-gradient(90deg, transparent 0%, ${glow} 50%, transparent 100%)`,
      }} />
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-2 h-2 rounded-full"
        style={{ background: glow, boxShadow: `0 0 12px 3px ${glow}` }} />
    </div>
  </div>
);

export const LandingPage: React.FC<LandingPageProps> = ({
  onStartIntake,
  onSelectSample,
  samples,
}) => {
  return (
    <div className="relative z-10 w-full overflow-x-hidden">
      {/* 1. Full-screen Hero with parallax & floating stickers */}
      <HeroSection onStartIntake={onStartIntake} onSelectSample={onSelectSample} />

      {/* ── Divider */}
      <SectionDivider glow="rgba(239,68,68,0.4)" />

      {/* 2. Act I: Sticky scroll comparison — Legacy vs GRAPH_Z3 */}
      <StoryPrologue />

      {/* ── Divider */}
      <SectionDivider glow="rgba(56,189,248,0.4)" />

      {/* 3. Act II: GNN CFG Explorer */}
      <StoryChapter1 />

      {/* ── Divider */}
      <SectionDivider glow="rgba(168,85,247,0.4)" />

      {/* 4. Act III: Z3 SMT Formal Verification */}
      <StoryChapter2 />

      {/* ── Divider */}
      <SectionDivider glow="rgba(251,146,60,0.4)" />

      {/* 5. Act IV: Exploit Primitive Synthesis */}
      <StoryChapter3 />

      {/* ── Divider */}
      <SectionDivider glow="rgba(16,185,129,0.4)" />

      {/* 6. Act V: Automated AI Remediation */}
      <StoryChapter4 />

      {/* ── Divider */}
      <SectionDivider glow="rgba(99,102,241,0.4)" />

      {/* 7. Industry Benchmark Matrix */}
      <div className="max-w-6xl mx-auto">
        <BenchmarkComparison />
      </div>

      {/* ── Divider */}
      <SectionDivider />

      {/* 8. Live Cyber Terminal Simulation */}
      <div className="max-w-6xl mx-auto">
        <InteractiveTerminal />
      </div>

      {/* ── Divider */}
      <SectionDivider />

      {/* 9. Interactive Binary Sandbox */}
      <div className="max-w-6xl mx-auto">
        <InteractiveSandbox
          onStartIntake={onStartIntake}
          onSelectSample={onSelectSample}
          samples={samples}
        />
      </div>

      {/* ── Divider */}
      <SectionDivider glow="rgba(52,211,153,0.4)" />

      {/* 10. Compliance & Standards Badges */}
      <div className="max-w-6xl mx-auto">
        <SecurityAuditorsBadge />
      </div>

      {/* 11. Cyber Footer */}
      <CyberFooter />
    </div>
  );
};
