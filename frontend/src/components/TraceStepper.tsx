import React, { useState, useEffect } from 'react';
import { Play, Pause, SkipBack, SkipForward, ChevronLeft, ChevronRight } from 'lucide-react';
import type { ExecutionState } from '../types';

interface TraceStepperProps {
  trace: ExecutionState[];
  currentStep: number;
  onStepChange: (step: number) => void;
}

export const TraceStepper: React.FC<TraceStepperProps> = ({ trace, currentStep, onStepChange }) => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [playbackSpeed, setPlaybackSpeed] = useState(1);
  const [hideLib, setHideLib] = useState(false);

  const totalSteps = trace.length;
  const currentState: ExecutionState | undefined = trace[currentStep];

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
      {/* Player Controller Strip */}
      <div className="flex flex-col items-center justify-between gap-4 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 md:flex-row backdrop-blur-sm">
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            onClick={() => onStepChange(0)}
            className="rounded-md border border-zinc-800 bg-zinc-950 p-2 text-zinc-400 hover:text-white transition-colors"
            title="First step"
          >
            <SkipBack className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={handlePrev}
            disabled={currentStep === 0}
            className="rounded-md border border-zinc-800 bg-zinc-950 p-2 text-zinc-400 hover:text-white disabled:opacity-30 transition-colors"
            title="Previous step"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={() => setIsPlaying(!isPlaying)}
            className="btn-signal !px-4 !py-1.5"
          >
            {isPlaying ? (
              <>
                <Pause className="h-3.5 w-3.5 fill-current" />
                <span>Pause</span>
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5 fill-current" />
                <span>Play</span>
              </>
            )}
          </button>
          <button
            type="button"
            onClick={handleNext}
            disabled={currentStep >= totalSteps - 1}
            className="rounded-md border border-zinc-800 bg-zinc-950 p-2 text-zinc-400 hover:text-white disabled:opacity-30 transition-colors"
            title="Next step"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={() => onStepChange(totalSteps - 1)}
            className="rounded-md border border-zinc-800 bg-zinc-950 p-2 text-zinc-400 hover:text-white transition-colors"
            title="Last step"
          >
            <SkipForward className="h-4 w-4" />
          </button>
        </div>

        {/* Progress Timeline Slider */}
        <div className="flex w-full flex-1 items-center gap-3">
          <input
            type="range"
            min={0}
            max={totalSteps - 1}
            value={currentStep}
            onChange={(e) => onStepChange(Number(e.target.value))}
            className="h-1.5 w-full cursor-pointer accent-emerald-500"
          />
          <span className="min-w-[70px] text-right font-mono text-xs text-zinc-300">
            {currentStep + 1} / {totalSteps}
          </span>
        </div>

        {/* Speed & Options */}
        <div className="flex items-center gap-3 text-xs text-zinc-400">
          <select
            value={playbackSpeed}
            onChange={(e) => setPlaybackSpeed(Number(e.target.value))}
            className="rounded-md border border-zinc-800 bg-zinc-950 px-2 py-1 text-emerald-400 outline-none"
          >
            <option value={1}>1x Speed</option>
            <option value={2}>2x Speed</option>
            <option value={4}>4x Speed</option>
          </select>

          <label className="flex cursor-pointer items-center gap-1.5 select-none">
            <input
              type="checkbox"
              checked={hideLib}
              onChange={(e) => setHideLib(e.target.checked)}
              className="accent-emerald-500 rounded"
            />
            <span>Skip Libs</span>
          </label>
        </div>
      </div>

      {/* State Inspector Card */}
      {currentState && (
        <div className="space-y-4 rounded-xl border border-zinc-800 bg-zinc-950 p-6 shadow-xl">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-zinc-800 pb-3">
            <div className="flex items-center gap-3">
              <span className="rounded bg-emerald-500/10 border border-emerald-500/30 px-2.5 py-1 text-xs text-emerald-400 font-bold">
                Step #{currentStep + 1}
              </span>
              <span className="text-sm font-semibold text-zinc-100">{currentState.function_name}</span>
              <span className="text-xs text-zinc-500">@{currentState.instruction_address}</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              <span
                className={`rounded px-2.5 py-0.5 uppercase font-bold border ${
                  isSat ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-400' : 'border-rose-500/40 bg-rose-500/10 text-rose-400'
                }`}
              >
                SMT: {smtDiag?.status || 'SAT'}
              </span>
              <span className="rounded border border-zinc-800 bg-zinc-900 px-2.5 py-0.5 text-zinc-400">
                Depth: {currentState.execution_depth}
              </span>
            </div>
          </div>

          <p className="font-sans text-xs leading-relaxed text-zinc-300">{currentState.explanation}</p>

          {smtDiag?.constraint_annotations && smtDiag.constraint_annotations.length > 0 && (
            <div className="space-y-1.5 pt-2">
              <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">
                Path Constraints ({smtDiag.constraint_annotations.length})
              </span>
              <div className="max-h-36 space-y-1 overflow-y-auto pr-2">
                {smtDiag.constraint_annotations.map((c, i) => (
                  <div key={i} className="rounded border border-zinc-800/80 bg-zinc-900/60 p-2 text-xs leading-relaxed text-emerald-300">
                    {c}
                  </div>
                ))}
              </div>
            </div>
          )}

          {smtDiag?.model && (
            <div className="space-y-1.5 pt-2">
              <span className="text-[11px] font-semibold text-zinc-400 uppercase tracking-wider">
                Satisfying Assignment Model
              </span>
              <pre className="overflow-x-auto rounded border border-zinc-800/80 bg-zinc-900/60 p-3 text-xs text-emerald-400 font-mono">
                {smtDiag.model}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
