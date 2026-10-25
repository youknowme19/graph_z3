import React from 'react';
import { ArrowRight, Upload, Cpu } from 'lucide-react';
import type { SampleBinary } from '../types';

interface InteractiveSandboxProps {
  onStartIntake: () => void;
  onSelectSample: (sampleId: string) => void;
  samples: SampleBinary[];
}

export const InteractiveSandbox: React.FC<InteractiveSandboxProps> = ({
  onStartIntake,
  onSelectSample,
  samples,
}) => {
  return (
    <section id="sandbox" className="relative px-4 py-16 sm:px-6 lg:px-8 border-t border-border">
      <div className="mx-auto max-w-7xl space-y-8">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
          <div>
            <div className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-rose-500 font-semibold">
              <Cpu className="h-3.5 w-3.5" />
              <span>Verification Sandbox</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-primary sm:text-3xl mt-1">
              Select a Test Target or Drop Your Binary
            </h2>
          </div>
          <p className="max-w-md text-xs text-secondary">
            Every sample initiates a real run against the <code className="text-rose-500 font-mono">/api/analyze</code> endpoint. No canned demonstrations.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {samples.map((sample) => (
            <button
              key={sample.id}
              type="button"
              onClick={() => onSelectSample(sample.id)}
              className="group flex flex-col justify-between rounded-xl border border-border bg-surface p-5 text-left transition-all duration-200 hover:border-rose-500/50 hover:bg-surface-raised hover:shadow-lg hover:shadow-rose-950/10"
            >
              <div>
                <div className="flex items-center justify-between">
                  <span
                    className={`rounded px-2 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider border ${
                      sample.severity === 'CRITICAL'
                        ? 'border-rose-500/30 bg-rose-500/10 text-rose-400'
                        : sample.severity === 'HIGH'
                          ? 'border-amber-500/30 bg-amber-500/10 text-amber-400'
                          : 'border-border bg-surface-raised text-secondary'
                    }`}
                  >
                    {sample.severity}
                  </span>
                  <span className="font-mono text-xs text-secondary">
                    {sample.cwe || sample.category}
                  </span>
                </div>

                <h3 className="mt-4 font-semibold text-base text-primary group-hover:text-rose-400 transition-colors">
                  {sample.name}
                </h3>
                <p className="mt-1.5 text-xs text-secondary leading-relaxed line-clamp-2">
                  {sample.description}
                </p>
              </div>

              <div className="mt-6 flex items-center justify-between border-t border-border pt-3 text-xs font-mono">
                <span className="text-muted">{sample.arch || 'AArch64'}</span>
                <span className="inline-flex items-center gap-1 font-semibold text-rose-500 transition-transform group-hover:translate-x-0.5">
                  <span>Analyze</span>
                  <ArrowRight className="h-3.5 w-3.5" />
                </span>
              </div>
            </button>
          ))}

          {/* Custom Upload Card */}
          <button
            type="button"
            onClick={onStartIntake}
            className="group flex flex-col items-center justify-center rounded-xl border border-dashed border-border bg-surface/50 p-6 text-center transition-all duration-200 hover:border-rose-500 hover:bg-surface-raised"
          >
            <div className="rounded-full bg-surface-raised p-3 text-primary group-hover:bg-rose-500/10 group-hover:text-rose-400 transition-colors border border-border">
              <Upload className="h-5 w-5" />
            </div>
            <h3 className="mt-3 font-semibold text-sm text-primary">
              Upload Custom Binary
            </h3>
            <p className="mt-1 text-xs text-secondary max-w-xs">
              Supports Linux ELF, macOS Mach-O, and Windows PE formats.
            </p>
            <span className="mt-4 inline-flex items-center gap-1 font-mono text-xs font-medium text-rose-500">
              <span>Open Intake</span>
              <ArrowRight className="h-3 w-3" />
            </span>
          </button>
        </div>
      </div>
    </section>
  );
};
