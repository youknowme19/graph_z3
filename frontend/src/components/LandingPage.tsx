import React from 'react';
import { HeroCinematic3D } from './HeroCinematic3D';
import { ProductIntroSection } from './ProductIntroSection';
import { SecurityAuditorsBadge } from './SecurityAuditorsBadge';
import { FinalCTA } from './FinalCTA';
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
}) => {
  return (
    <div className="relative z-10 w-full">
      {/* Cinematic 3D Storytelling & Physical Transition to Workbench */}
      <HeroCinematic3D
        onStartAnalysis={onStartIntake}
        onExploreDemo={() => onSelectSample('cwe120_buffer_overflow')}
      />

      {/* Operational Workbench & Core Capability Pillars */}
      <ProductIntroSection
        onOpenWorkspace={onStartIntake}
        onSelectSample={onSelectSample}
      />

      {/* Enterprise & DevSecOps Integrations */}
      <SecurityAuditorsBadge />

      {/* Final Call to Action */}
      <FinalCTA onGetStarted={onStartIntake} />

      {/* Footer */}
      <CyberFooter />
    </div>
  );
};
