import React, { useState, useEffect } from 'react';
import {
  Play,
  Pause,
  SkipBack,
  SkipForward,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import type { ExecutionState } from '../types';

interface TraceStepperProps {
  trace: ExecutionState[];
  currentStep: number;
  onStepChange: (step: number) => void;
}

export const TraceStepper: React.FC<TraceStepperProps> = ({
  trace,
  currentStep,
  onStepChange,
}) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1); // 1x, 2x, 4x
  const [hideLib, setHideLib] = useState(false);

  const totalSteps = trace.length;
  const currentState: ExecutionState | undefined = trace[currentStep];

  // Auto-play timer
  useEffect(() => {
    if (!isPlaying || totalSteps === 0) return;

    const interval = setInterval(() => {
      if (currentStep >= totalSteps - 1) {
        setIsPlaying(false);
        return;
      }
      let next = currentStep + 1;
      if (hideLib) {
        while (next < totalSteps - 1 && trace[next]?.is_library) {
          next++;
        }
      }
      onStepChange(next);
    }, 1000 / playbackSpeed);

    return () => clearInterval(interval);
  }, [isPlaying, totalSteps, playbackSpeed, hideLib, trace, currentStep, onStepChange]);

  const handlePrev = () => {
    let next = Math.max(0, currentStep - 1);
    if (hideLib) {
      while (next > 0 && trace[next]?.is_library) {
        next--;
      }
    }
    onStepChange(next);
  };

  const handleNext = () => {
    let next = Math.min(totalSteps - 1, currentStep + 1);
    if (hideLib) {
      while (next < totalSteps - 1 && trace[next]?.is_library) {
        next++;
      }
    }
    onStepChange(next);
  };

  if (totalSteps === 0) {
    return null;
  }

  const smtDiag = currentState?.smt_diagnostics;
  const isSat = smtDiag?.status === 'SAT';

  return (
    <div className="w-full space-y-4 font-mono">
      {/* Playback Control Bar */}
      <div className="p-4 rounded-2xl bg-slate-900/80 border border-slate-800 flex flex-col md:flex-row items-center justify-between gap-4">
        {/* Play/Step Buttons */}
        <div className="flex items-center gap-1.5">
          <button
            onClick={() => onStepChange(0)}
            className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-cyan-400"
            title="First Step"
          >
            <SkipBack className="w-4 h-4" />
          </button>
          <button
            onClick={handlePrev}
            disabled={currentStep === 0}
            className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-cyan-400 disabled:opacity-40"
            title="Previous Step"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => setIsPlaying(!isPlaying)}
            className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-xs flex items-center gap-1.5 transition-colors shadow-md shadow-cyan-500/20"
          >
            {isPlaying ? (
              <>
                <Pause className="w-4 h-4 fill-slate-950" />
                <span>PAUSE</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-slate-950" />
                <span>PLAY</span>
              </>
            )}
          </button>
          <button
            onClick={handleNext}
            disabled={currentStep >= totalSteps - 1}
            className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-cyan-400 disabled:opacity-40"
            title="Next Step"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
          <button
            onClick={() => onStepChange(totalSteps - 1)}
            className="p-2 rounded-lg bg-slate-950 border border-slate-800 text-slate-400 hover:text-cyan-400"
            title="Last Step"
          >
            <SkipForward className="w-4 h-4" />
          </button>
        </div>

        {/* Scrubber Range Slider */}
        <div className="flex-1 w-full flex items-center gap-3">
          <input
            type="range"
            min={0}
            max={totalSteps - 1}
            value={currentStep}
            onChange={(e) => onStepChange(Number(e.target.value))}
            className="w-full accent-cyan-400 bg-slate-800 rounded-lg h-2 cursor-pointer"
          />
          <span className="text-xs text-slate-300 font-bold whitespace-nowrap min-w-[70px] text-right">
            {currentStep + 1} / {totalSteps}
          </span>
        </div>

        {/* Speed & Options */}
        <div className="flex items-center gap-3 text-xs text-slate-400">
          <select
            value={playbackSpeed}
            onChange={(e) => setPlaybackSpeed(Number(e.target.value))}
            className="px-2 py-1 rounded bg-slate-950 border border-slate-800 text-cyan-400 font-bold outline-none"
          >
            <option value={1}>1x Speed</option>
            <option value={2}>2x Speed</option>
            <option value={4}>4x Speed</option>
          </select>

          <label className="flex items-center gap-1.5 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={hideLib}
              onChange={(e) => setHideLib(e.target.checked)}
              className="accent-cyan-400 rounded"
            />
            <span>Skip Libs</span>
          </label>
        </div>
      </div>

      {/* State Inspector Details Card */}
      {currentState && (
        <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-4">
          {/* Header Row */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-1 rounded bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-xs font-bold">
                STATE #{currentStep + 1}
              </span>
              <span className="text-sm font-bold text-slate-100">
                {currentState.function_name}
              </span>
              <span className="text-xs text-slate-400">
                @{currentState.instruction_address}
              </span>
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span
                className={`px-2 py-0.5 rounded uppercase font-bold ${
                  isSat
                    ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                    : 'bg-red-500/10 border border-red-500/30 text-red-400'
                }`}
              >
                SMT: {smtDiag?.status || 'SAT'}
              </span>
              <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                Depth: {currentState.execution_depth}
              </span>
            </div>
          </div>

          {/* Explanation Text */}
          <p className="text-xs text-slate-300 font-sans leading-relaxed">
            {currentState.explanation}
          </p>

          {/* SMT Constraint Annotations */}
          {smtDiag?.constraint_annotations && smtDiag.constraint_annotations.length > 0 && (
            <div className="space-y-1.5 pt-2">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Path Constraints ({smtDiag.constraint_annotations.length})
              </span>
              <div className="space-y-1 max-h-36 overflow-y-auto pr-2">
                {smtDiag.constraint_annotations.map((c, i) => (
                  <div
                    key={i}
                    className="p-2 rounded bg-slate-950 border border-slate-800/80 text-[11px] text-cyan-300/90 leading-relaxed"
                  >
                    {c}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Concrete Model Values if Available */}
          {smtDiag?.model && (
            <div className="space-y-1.5 pt-2">
              <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider">
                Satisfying Assignment Model
              </span>
              <pre className="p-3 rounded bg-[#06080e] border border-slate-800 text-[11px] text-purple-300 overflow-x-auto">
                {smtDiag.model}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
