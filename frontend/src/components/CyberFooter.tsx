import React from 'react';
import { BRAND } from '../config/brand';
import { Shield } from 'lucide-react';

export const CyberFooter: React.FC = () => {
  return (
    <footer className="relative border-t border-border bg-canvas px-4 py-12 sm:px-6 lg:px-8 transition-colors">
      <div className="mx-auto max-w-7xl">
        <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span className="flex h-6 w-6 items-center justify-center rounded bg-rose-500/10 text-rose-500 font-mono text-xs font-bold border border-rose-500/20">
                <Shield className="h-3.5 w-3.5" />
              </span>
              <span className="font-extrabold text-sm tracking-tight text-primary">
                {BRAND.wordmark}
              </span>
            </div>
            <p className="text-xs text-secondary leading-relaxed">
              Next-generation binary defense and mathematical exploit verification.
            </p>
          </div>

          <div className="flex items-center gap-6 text-xs text-secondary">
            <span>Formal Verification</span>
            <span>Path Pruning</span>
            <span>Exploit Synthesis</span>
          </div>
        </div>

        <div className="mt-8 border-t border-border pt-6 flex flex-col sm:flex-row sm:items-center justify-between text-xs text-secondary">
          <p>© 2026 {BRAND.name} Systems. Enterprise Binary Defense Platform.</p>
          <p className="font-mono text-[11px] mt-2 sm:mt-0 text-muted">Mathematical verification over compiled binaries</p>
        </div>
      </div>
    </footer>
  );
};
