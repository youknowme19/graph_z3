import React, { useState, useRef } from 'react';
import { Upload, Sliders, Play, CheckCircle2, Cpu, Hash, AlertCircle, FileCode } from 'lucide-react';
import type { SampleBinary } from '../types';

interface FileUploadProps {
  onStartAnalysis: (config: {
    token?: string;
    sampleId?: string;
    maxSteps: number;
    symbolicSize: number;
    enableGnn: boolean;
  }) => void;
  samples: SampleBinary[];
  isUploading: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({
  onStartAnalysis,
  samples,
  isUploading,
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [fileToken, setFileToken] = useState<string | null>(null);
  const [fileInfo, setFileInfo] = useState<{
    size: number;
    sha256?: string;
    arch_hint?: string;
  } | null>(null);
  const [selectedSampleId, setSelectedSampleId] = useState<string | null>(null);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [maxSteps, setMaxSteps] = useState(300);
  const [symbolicSize, setSymbolicSize] = useState(32);
  const [enableGnn, setEnableGnn] = useState(true);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleUploadFile = async (file: File) => {
    setSelectedFile(file);
    setSelectedSampleId(null);
    setUploadError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed with status: ${response.status}`);
      }

      const data = await response.json();
      setFileToken(data.token);
      setFileInfo({
        size: data.size,
        sha256: data.sha256,
        arch_hint: data.arch_hint,
      });
    } catch (err: unknown) {
      setUploadError(err instanceof Error ? err.message : 'Failed to upload binary.');
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleUploadFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      handleUploadFile(e.target.files[0]);
    }
  };

  const handleSelectSample = (id: string) => {
    setSelectedSampleId(id);
    setSelectedFile(null);
    setFileToken(null);
    setFileInfo(null);
    setUploadError(null);
  };

  const handleLaunch = () => {
    if (!fileToken && !selectedSampleId) {
      setUploadError('Please upload a binary file or select a benchmark target.');
      return;
    }

    onStartAnalysis({
      token: fileToken || undefined,
      sampleId: selectedSampleId || undefined,
      maxSteps,
      symbolicSize,
      enableGnn,
    });
  };

  return (
    <div className="relative z-10 mx-auto w-full max-w-6xl space-y-8 px-4 py-8 sm:px-6">
      {/* Header */}
      <div className="space-y-1.5">
        <div className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-emerald-400 font-semibold">
          <FileCode className="h-3.5 w-3.5" />
          <span>Scan Intake & Solver Bounds</span>
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-zinc-100 sm:text-3xl">
          Target Ingestion & Configuration
        </h2>
        <p className="max-w-xl text-xs text-zinc-400">
          Upload any compiled executable (ELF, Mach-O, PE) or pick a test benchmark. Fine-tune symbolic depth limits and SageConv graph inference.
        </p>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
        {/* Left Column: Dropzone & Benchmark Picker */}
        <div className="space-y-5 lg:col-span-7">
          {/* Dropzone */}
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') fileInputRef.current?.click();
            }}
            role="button"
            tabIndex={0}
            className={`flex min-h-[220px] cursor-pointer flex-col items-center justify-center rounded-xl border border-dashed p-6 text-center transition-all ${
              dragActive
                ? 'border-emerald-500 bg-emerald-500/10'
                : selectedFile
                  ? 'border-emerald-500/60 bg-emerald-500/5'
                  : 'border-border bg-surface hover:border-border hover:bg-surface-hover'
            }`}
          >
            <input ref={fileInputRef} type="file" onChange={handleFileChange} className="hidden" />
            <div className="rounded-full bg-surface-raised p-3 text-emerald-500 dark:text-emerald-400 mb-3 border border-border">
              <Upload className="h-5 w-5" />
            </div>

            {selectedFile ? (
              <div className="space-y-1">
                <div className="flex items-center justify-center gap-2 text-sm font-semibold text-emerald-500 dark:text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>{selectedFile.name}</span>
                </div>
                <p className="font-mono text-xs text-secondary">
                  {(selectedFile.size / 1024).toFixed(1)} KB · {fileInfo?.arch_hint || 'Native Binary'}
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                <p className="text-sm font-medium text-primary">
                  Drop target binary here, or <span className="text-emerald-500 dark:text-emerald-400 underline underline-offset-4">browse</span>
                </p>
                <p className="text-xs text-muted">Supports Linux ELF, macOS Mach-O, Windows PE</p>
              </div>
            )}
          </div>

          {/* Uploaded File Metadata card */}
          {fileInfo && (
            <div className="rounded-lg border border-border bg-surface-raised p-3.5 font-mono text-xs space-y-1.5">
              <div className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-secondary">
                  <Cpu className="h-3.5 w-3.5 text-emerald-500 dark:text-emerald-400" /> Architecture
                </span>
                <span className="text-primary font-semibold">{fileInfo.arch_hint}</span>
              </div>
              {fileInfo.sha256 && (
                <div className="flex items-center justify-between gap-4">
                  <span className="flex items-center gap-1.5 text-secondary">
                    <Hash className="h-3.5 w-3.5 text-muted" /> SHA-256
                  </span>
                  <span className="max-w-[280px] truncate text-secondary">{fileInfo.sha256}</span>
                </div>
              )}
            </div>
          )}

          {/* Benchmark Picker */}
          <div className="space-y-2">
            <span className="font-mono text-xs uppercase tracking-wider text-secondary font-medium">
              Or Select A Research Benchmark
            </span>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {samples.map((sample) => {
                const isSelected = selectedSampleId === sample.id;
                return (
                  <button
                    key={sample.id}
                    type="button"
                    onClick={() => handleSelectSample(sample.id)}
                    className={`flex flex-col rounded-lg border p-3 text-left transition-colors ${
                      isSelected
                        ? 'border-emerald-500/60 bg-emerald-500/10'
                        : 'border-border bg-surface hover:border-border hover:bg-surface-hover'
                    }`}
                  >
                    <div className="flex w-full items-center justify-between">
                      <span className="font-mono text-[10px] uppercase text-muted">
                        {sample.category}
                      </span>
                      <span
                        className={`font-mono text-[10px] font-bold ${
                          sample.severity === 'CRITICAL' ? 'text-rose-500 dark:text-rose-400' : 'text-amber-500 dark:text-amber-400'
                        }`}
                      >
                        {sample.severity}
                      </span>
                    </div>
                    <span className="mt-1 font-semibold text-xs text-primary truncate">{sample.name}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {uploadError && (
            <div className="flex items-center gap-2 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-500 dark:text-rose-300">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}
        </div>

        {/* Right Column: Solver Tuning Parameters */}
        <div className="lg:col-span-5">
          <div className="space-y-6 rounded-xl border border-border bg-surface p-6 shadow-sm">
            <div className="flex items-center gap-2 border-b border-border pb-3">
              <Sliders className="h-4 w-4 text-emerald-500 dark:text-emerald-400" />
              <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-primary">
                Engine & Solver Parameters
              </h3>
            </div>

            {/* Depth Slider */}
            <div className="space-y-2">
              <div className="flex justify-between font-mono text-xs">
                <span className="text-secondary">Max Symbolic Depth</span>
                <span className="font-bold text-emerald-500 dark:text-emerald-400">{maxSteps} steps</span>
              </div>
              <input
                type="range"
                min={50}
                max={1000}
                step={50}
                value={maxSteps}
                onChange={(e) => setMaxSteps(Number(e.target.value))}
                className="w-full cursor-pointer accent-emerald-500"
              />
              <span className="block text-[11px] text-muted leading-tight">
                Maximum basic block execution slice before timeout.
              </span>
            </div>

            {/* Symbolic Size Slider */}
            <div className="space-y-2">
              <div className="flex justify-between font-mono text-xs">
                <span className="text-secondary">Symbolic Input Buffer</span>
                <span className="font-bold text-emerald-500 dark:text-emerald-400">{symbolicSize} bytes</span>
              </div>
              <input
                type="range"
                min={8}
                max={128}
                step={8}
                value={symbolicSize}
                onChange={(e) => setSymbolicSize(Number(e.target.value))}
                className="w-full cursor-pointer accent-emerald-500"
              />
              <span className="block text-[11px] text-muted leading-tight">
                Length of symbolic bitvector injected into stdin buffers.
              </span>
            </div>

            {/* GraphSAGE Toggle */}
            <label className="flex cursor-pointer items-center justify-between border-t border-border pt-4">
              <div className="space-y-0.5">
                <span className="block text-xs font-semibold text-primary">GraphSAGE Pre-Filter</span>
                <span className="block text-[11px] text-muted">
                  Prunes 99.6% benign paths using SageConv risk scores.
                </span>
              </div>
              <input
                type="checkbox"
                checked={enableGnn}
                onChange={(e) => setEnableGnn(e.target.checked)}
                className="h-4 w-4 rounded accent-emerald-500"
              />
            </label>

            {/* Execute Launch Button */}
            <button
              type="button"
              onClick={handleLaunch}
              disabled={isUploading}
              className="btn-signal w-full py-2.5 text-xs font-bold"
            >
              <Play className="h-4 w-4 fill-current" />
              <span>{isUploading ? 'Engine Initializing…' : 'Execute Neuro-Symbolic Analysis'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
