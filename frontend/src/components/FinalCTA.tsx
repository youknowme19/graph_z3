import React from 'react';
import { ArrowRight, ChevronUp, Terminal } from 'lucide-react';
import { BRAND } from '../config/brand';

interface FinalCTAProps {
  onGetStarted: () => void;
}

export const FinalCTA: React.FC<FinalCTAProps> = ({ onGetStarted }) => {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <section className="relative px-4 py-20 sm:px-6 lg:px-8 border-t border-border bg-canvas">
      <div className="mx-auto max-w-4xl text-center space-y-6">
        <h2 className="text-3xl font-extrabold tracking-tight sm:text-5xl text-primary">
          {BRAND.finalCtaHeadline}
        </h2>

        <p className="text-base sm:text-lg text-secondary max-w-xl mx-auto leading-relaxed">
          {BRAND.finalCtaSubtext}
        </p>

        <div className="flex flex-wrap items-center justify-center gap-4 pt-4">
          <button
            type="button"
            onClick={onGetStarted}
            className="btn-signal group text-sm !px-6 !py-3"
          >
            <span>Launch Analysis</span>
            <ArrowRight className="h-4 w-4 transition-transform group-hover:translate-x-1" />
          </button>

          <button
            type="button"
            onClick={scrollToTop}
            className="btn-secondary text-sm !px-6 !py-3"
          >
            <Terminal className="h-4 w-4 text-rose-500" />
            <span>Review Threat Story</span>
          </button>
        </div>

        {/* Return to top */}
        <div className="pt-12">
          <button
            type="button"
            onClick={scrollToTop}
            className="inline-flex items-center gap-2 font-mono text-xs text-muted hover:text-rose-500 transition-colors"
          >
            <ChevronUp className="h-4 w-4" />
            <span>Return to top</span>
          </button>
        </div>
      </div>
    </section>
  );
};
