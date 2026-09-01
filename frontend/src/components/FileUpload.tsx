import React, { useState, useRef } from 'react';
import {
  Upload,
  Sliders,
  Play,
  CheckCircle2,
  Cpu,
  Hash,
  AlertCircle,
} from 'lucide-react';
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

  // Analysis Parameters
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
    } catch (err: any) {
      setUploadError(err.message || 'Failed to upload binary.');
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
      setUploadError('Please upload a binary file or select a sample benchmark.');
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
    <div className="relative z-10 w-full max-w-5xl mx-auto px-4 sm:px-6 py-8 space-y-8">
      <div className="text-center space-y-2">
        <h2 className="text-2xl sm:text-3xl font-extrabold text-slate-100">
          Target Intake & Engine Configuration
        </h2>
        <p className="text-xs sm:text-sm text-slate-400 max-w-xl mx-auto">
          Drop an ELF, Mach-O, or PE binary, or choose from pre-configured verification suites.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Left Column: Drag & Drop Intake */}
        <div className="lg:col-span-7 space-y-6">
          <div
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={`relative rounded-2xl border-2 border-dashed p-8 text-center cursor-pointer transition-all flex flex-col items-center justify-center min-h-[260px] ${
              dragActive
                ? 'border-cyan-400 bg-cyan-950/30 shadow-lg shadow-cyan-500/10'
                : selectedFile
                ? 'border-emerald-500/60 bg-emerald-950/10'
                : 'border-slate-800 bg-slate-900/40 hover:border-slate-700 hover:bg-slate-900/70'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileChange}
              className="hidden"
            />

            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 mb-4">
              <Upload className="w-7 h-7" />
            </div>

            {selectedFile ? (
              <div className="space-y-2">
                <div className="flex items-center justify-center gap-2 text-emerald-400 font-semibold text-sm">
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Target Loaded: {selectedFile.name}</span>
                </div>
                <p className="text-xs font-mono text-slate-400">
                  {(selectedFile.size / 1024).toFixed(1)} KB &bull;{' '}
                  {fileInfo?.arch_hint || 'Native Executable'}
                </p>
              </div>
            ) : (
              <div className="space-y-1">
                <p className="text-sm font-bold text-slate-200">
                  Drop executable binary here, or{' '}
                  <span className="text-cyan-400 underline underline-offset-4">browse</span>
                </p>
                <p className="text-xs text-slate-400">
                  Supports Linux x86_64 / ARM ELF, macOS Mach-O, Windows PE
                </p>
              </div>
            )}
          </div>

          {/* Uploaded File Info Card */}
          {fileInfo && (
            <div className="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 text-xs font-mono">
              <div className="flex items-center justify-between text-slate-300">
                <span className="flex items-center gap-1.5 text-slate-400">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400" /> Arch
                </span>
                <span className="text-cyan-400 font-bold">{fileInfo.arch_hint}</span>
              </div>
              {fileInfo.sha256 && (
                <div className="flex items-center justify-between text-slate-300">
                  <span className="flex items-center gap-1.5 text-slate-400">
                    <Hash className="w-3.5 h-3.5 text-blue-400" /> SHA-256
                  </span>
                  <span className="text-slate-400 truncate max-w-[280px]">
                    {fileInfo.sha256}
                  </span>
                </div>
              )}
            </div>
          )}

          {/* Sample Selectors */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400 font-semibold uppercase tracking-wider font-mono">
                Or Select Benchmark Target
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {samples.map((sample) => {
                const isSelected = selectedSampleId === sample.id;
                return (
                  <button
                    key={sample.id}
                    onClick={() => handleSelectSample(sample.id)}
                    className={`p-3 rounded-xl border text-left transition-all flex flex-col justify-between ${
                      isSelected
                        ? 'border-cyan-500 bg-cyan-950/20 text-slate-100 shadow-sm'
                        : 'border-slate-800/80 bg-slate-900/40 hover:border-slate-700 text-slate-300'
                    }`}
                  >
                    <div className="flex items-center justify-between w-full mb-1">
                      <span className="text-[10px] font-mono text-cyan-400 font-semibold uppercase">
                        {sample.category}
                      </span>
                      <span
                        className={`text-[9px] font-mono font-bold px-1.5 py-0.2 rounded ${
                          sample.severity === 'CRITICAL'
                            ? 'bg-red-500/10 text-red-400'
                            : 'bg-orange-500/10 text-orange-400'
                        }`}
                      >
                        {sample.severity}
                      </span>
                    </div>
                    <span className="text-xs font-bold truncate">{sample.name}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {uploadError && (
            <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{uploadError}</span>
            </div>
          )}
        </div>

        {/* Right Column: Engine Parameters & Launch */}
        <div className="lg:col-span-5 space-y-6">
          <div className="p-6 rounded-2xl bg-slate-900/60 border border-slate-800 space-y-6">
            <div className="flex items-center gap-2 border-b border-slate-800/80 pb-4">
              <Sliders className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono">
                Solver Engine Tuning
              </h3>
            </div>

            {/* Max Steps Slider */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300">Max Symbolic Depth</span>
                <span className="text-cyan-400 font-bold">{maxSteps} steps</span>
              </div>
              <input
                type="range"
                min={50}
                max={1000}
                step={50}
                value={maxSteps}
                onChange={(e) => setMaxSteps(Number(e.target.value))}
                className="w-full accent-cyan-400 bg-slate-800 rounded-lg h-1.5 cursor-pointer"
              />
              <span className="text-[10px] text-slate-400 block">
                Upper bound on basic block execution trace before path truncation.
              </span>
            </div>

            {/* Symbolic Input Buffer Size */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-slate-300">Symbolic Buffer Size</span>
                <span className="text-cyan-400 font-bold">{symbolicSize} Bytes</span>
              </div>
              <input
                type="range"
                min={8}
                max={128}
                step={8}
                value={symbolicSize}
                onChange={(e) => setSymbolicSize(Number(e.target.value))}
                className="w-full accent-cyan-400 bg-slate-800 rounded-lg h-1.5 cursor-pointer"
              />
              <span className="text-[10px] text-slate-400 block">
                Length of symbolic byte bitvectors injected into stdin and memory buffers.
              </span>
            </div>

            {/* GNN Toggle */}
            <div className="pt-2 border-t border-slate-800/80 space-y-4">
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <span className="text-xs font-bold text-slate-200 block">
                    GNN SageConv Pre-Filter
                  </span>
                  <span className="text-[10px] text-slate-400">
                    Prioritize high-risk CFG functions to mitigate path explosion
                  </span>
                </div>
                <input
                  type="checkbox"
                  checked={enableGnn}
                  onChange={(e) => setEnableGnn(e.target.checked)}
                  className="w-4 h-4 rounded border-slate-700 bg-slate-800 text-cyan-500 focus:ring-0 focus:ring-offset-0 accent-cyan-400"
                />
              </label>
            </div>

            {/* Launch CTA */}
            <button
              onClick={handleLaunch}
              disabled={isUploading}
              className="w-full flex items-center justify-center gap-2 py-3.5 px-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold text-sm tracking-wide transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Play className="w-4 h-4 fill-slate-950" />
              <span>Execute Symbolic Fuzzing</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
