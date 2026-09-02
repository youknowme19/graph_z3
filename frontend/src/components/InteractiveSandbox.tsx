import React from 'react';
import { ArrowRight, Sparkles, UploadCloud } from 'lucide-react';
import { HoloSticker } from './HoloSticker';
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
    <section className="relative py-8 space-y-6">
      <div className="flex justify-center">
        <HoloSticker
          label="INTERACTIVE SANDBOX // ZERO-SETUP LAUNCHPAD"
          sublabel="Test pre-compiled vulnerable & secure targets"
          variant="holographic"
          rotation={-2}
          floatAnimation="tilt"
          icon={<Sparkles className="w-4 h-4 text-cyan-300" />}
        />
      </div>

      <div className="text-center space-y-2 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          Explore Ready-to-Verify{' '}
          <span className="bg-gradient-to-r from-cyan-400 via-teal-300 to-emerald-400 bg-clip-text text-transparent">
            Binary Targets
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          Select any of our pre-compiled benchmark binaries to witness the neuro-symbolic engine in action, or upload your own arbitrary ELF / Mach-O executable.
        </p>
      </div>

      {/* Target Grid */}
      <div className="max-w-5xl mx-auto px-4">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {samples.map((sample) => (
            <div
              key={sample.id}
              onClick={() => onSelectSample(sample.id)}
              className="metamask-card rounded-3xl p-6 flex flex-col justify-between space-y-4 cursor-pointer group relative overflow-hidden"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span
                    className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${
                      sample.severity === 'CRITICAL'
                        ? 'bg-red-950/80 text-red-300 border-red-800/80'
                        : sample.severity === 'HIGH'
                        ? 'bg-orange-950/80 text-orange-300 border-orange-800/80'
                        : sample.severity === 'MEDIUM'
                        ? 'bg-amber-950/80 text-amber-300 border-amber-800/80'
                        : 'bg-emerald-950/80 text-emerald-300 border-emerald-800/80'
                    }`}
                  >
                    {sample.severity}
                  </span>
                  <span className="text-xs font-mono text-cyan-400 font-bold">
                    {sample.cwe || sample.category}
                  </span>
                </div>

                <div className="font-mono text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
                  {sample.name}
                </div>

                <p className="text-slate-400 text-xs leading-relaxed">
                  {sample.description}
                </p>
              </div>

              <div className="pt-2 border-t border-slate-800 flex items-center justify-between font-mono text-xs">
                <span className="text-slate-500">{sample.arch || 'AArch64'}</span>
                <div className="flex items-center gap-1.5 text-cyan-400 group-hover:translate-x-1 transition-transform font-bold">
                  <span>Launch Analysis</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </div>
              </div>
            </div>
          ))}

          {/* Upload Custom Binary Card */}
          <div
            onClick={onStartIntake}
            className="metamask-card rounded-3xl p-6 border-dashed border-cyan-500/40 hover:border-cyan-400 flex flex-col items-center justify-center text-center space-y-3 cursor-pointer group bg-gradient-to-br from-cyan-950/10 to-slate-900"
          >
            <div className="w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
              <UploadCloud className="w-6 h-6" />
            </div>
            <div className="font-mono text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
              Upload Custom Binary
            </div>
            <p className="text-slate-400 text-xs max-w-xs">
              Drop any Mach-O or ELF binary (up to 50 MB) for full automated SMT verification.
            </p>
          </div>
        </div>
      </div>
    </section>
  );
};
