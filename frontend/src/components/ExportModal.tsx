import React, { useEffect, useRef } from 'react';
import { Download, FileCode, Globe, FileText, X } from 'lucide-react';
import type { AnalysisJob } from '../types';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysisJob: AnalysisJob | null;
}

export const ExportModal: React.FC<ExportModalProps> = ({ isOpen, onClose, analysisJob }) => {
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!isOpen) return;
    closeRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isOpen, onClose]);

  if (!isOpen || !analysisJob) return null;

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(analysisJob, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `vanta_scan_${analysisJob.binary_info?.filename || 'target'}.json`,
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="export-title"
        className="relative w-full max-w-lg space-y-5 rounded-xl border border-border bg-surface p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-border pb-3">
          <h3 id="export-title" className="font-mono text-xs font-semibold uppercase tracking-wider text-primary">
            Export Formal Telemetry & Artifacts
          </h3>
          <button
            ref={closeRef}
            type="button"
            onClick={onClose}
            className="rounded p-1 text-secondary hover:text-primary transition-colors"
            aria-label="Close"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-2.5">
          <a
            href={`/api/sarif/${analysisJob.id}`}
            download
            className="group flex items-center justify-between rounded-lg border border-border bg-surface-raised/40 p-4 transition-colors hover:border-rose-500/50 hover:bg-surface-raised"
          >
            <div className="flex items-center gap-3">
              <FileCode className="h-5 w-5 text-rose-500" />
              <div>
                <span className="block text-sm font-medium text-primary">OASIS SARIF 2.1.0</span>
                <span className="text-xs text-secondary">GitHub Advanced Security, GitLab, DefectDojo</span>
              </div>
            </div>
            <Download className="h-4 w-4 text-secondary group-hover:text-rose-500 transition-colors" />
          </a>

          <a
            href={`/api/report/${analysisJob.id}`}
            download
            className="group flex items-center justify-between rounded-lg border border-border bg-surface-raised/40 p-4 transition-colors hover:border-rose-500/50 hover:bg-surface-raised"
          >
            <div className="flex items-center gap-3">
              <Globe className="h-5 w-5 text-cyan-400" />
              <div>
                <span className="block text-sm font-medium text-primary">HTML Security Dossier</span>
                <span className="text-xs text-secondary">Interactive standalone audit report</span>
              </div>
            </div>
            <Download className="h-4 w-4 text-secondary group-hover:text-cyan-400 transition-colors" />
          </a>

          <button
            type="button"
            onClick={handleDownloadJson}
            className="group flex w-full items-center justify-between rounded-lg border border-border bg-surface-raised/40 p-4 text-left transition-colors hover:border-rose-500/50 hover:bg-surface-raised"
          >
            <div className="flex items-center gap-3">
              <FileText className="h-5 w-5 text-rose-400" />
              <div>
                <span className="block text-sm font-medium text-primary">Full JSON Diagnostics</span>
                <span className="text-xs text-secondary">Includes AST, CFG nodes, and Z3 models</span>
              </div>
            </div>
            <Download className="h-4 w-4 text-secondary group-hover:text-rose-400 transition-colors" />
          </button>
        </div>

        <div className="border-t border-border pt-3 text-right">
          <button
            type="button"
            onClick={onClose}
            className="btn-secondary !text-xs !py-1.5"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
