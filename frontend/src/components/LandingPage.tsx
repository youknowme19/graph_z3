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

export const LandingPage: React.FC<LandingPageProps> = ({
  onStartIntake,
  onSelectSample,
  samples,
}) => {
  return (
    <div className="relative z-10 w-full overflow-hidden">
      {/* 1. Hero Section with 3D Mouse Perspective & Floating HoloStickers */}
      <HeroSection
        onStartIntake={onStartIntake}
        onSelectSample={onSelectSample}
      />

      {/* 2. Act I: The Crisis of Blind Binary Fuzzing */}
      <StoryPrologue />

      {/* 3. Act II: The Neuro-Symbolic Synthesis (SageConv GNN) */}
      <StoryChapter1 />

      {/* 4. Act III: Mathematical Formal Verification (Z3 SMT Invariants) */}
      <StoryChapter2 />

      {/* 5. Act IV: Exploit Primitive Synthesis & Reproducers */}
      <StoryChapter3 />

      {/* 6. Act V: Automated AI Root Cause & Remediation Code Diff */}
      <StoryChapter4 />

      {/* 7. Industry Benchmark Matrix */}
      <BenchmarkComparison />

      {/* 8. Live Cyber Terminal Simulation */}
      <InteractiveTerminal />

      {/* 9. Interactive Sandbox & Binary Quick Launcher */}
      <InteractiveSandbox
        onStartIntake={onStartIntake}
        onSelectSample={onSelectSample}
        samples={samples}
      />

      {/* 10. Compliance & Enterprise Security Standards */}
      <SecurityAuditorsBadge />

      {/* 11. High-Tech Cyber Telemetry Footer */}
      <CyberFooter />
    </div>
  );
};
