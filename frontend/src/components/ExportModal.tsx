import React from 'react';
import { Download, FileCode, Globe, FileText, X } from 'lucide-react';
import type { AnalysisJob } from '../types';

interface ExportModalProps {
  isOpen: boolean;
  onClose: () => void;
  analysisJob: AnalysisJob | null;
}

export const ExportModal: React.FC<ExportModalProps> = ({
  isOpen,
  onClose,
  analysisJob,
}) => {
  if (!isOpen || !analysisJob) return null;

  const handleDownloadJson = () => {
    const dataStr =
      'data:text/json;charset=utf-8,' +
      encodeURIComponent(JSON.stringify(analysisJob, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute(
      'download',
      `graph_z3_scan_${analysisJob.binary_info?.filename || 'target'}.json`
    );
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
      <div className="relative w-full max-w-lg rounded-2xl bg-slate-900 border border-slate-800 shadow-2xl p-6 space-y-6">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-4">
          <div className="flex items-center gap-2.5">
            <Download className="w-5 h-5 text-cyan-400" />
            <h3 className="text-base font-bold text-slate-100 font-mono">
              EXPORT VERIFICATION TELEMETRY
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Options */}
        <div className="space-y-3">
          {/* SARIF 2.1.0 */}
          <a
            href={`/api/sarif/${analysisJob.id}`}
            download
            className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-cyan-500/50 transition-all group"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
                <FileCode className="w-5 h-5" />
              </div>
              <div>
                <span className="text-sm font-bold text-slate-100 group-hover:text-cyan-300 transition-colors block">
                  OASIS SARIF 2.1.0 Export
                </span>
                <span className="text-xs text-slate-400">
                  Standard format for GitHub Advanced Security & IDEs
                </span>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-cyan-400" />
          </a>

          {/* Standalone HTML Report */}
          <a
            href={`/api/report/${analysisJob.id}`}
            download
            className="flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-purple-500/50 transition-all group"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <span className="text-sm font-bold text-slate-100 group-hover:text-purple-300 transition-colors block">
                  Enterprise HTML / PDF Security Report
                </span>
                <span className="text-xs text-slate-400">
                  Self-contained interactive report with ERE verdicts
                </span>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-purple-400" />
          </a>

          {/* Raw JSON */}
          <button
            onClick={handleDownloadJson}
            className="w-full flex items-center justify-between p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-blue-500/50 transition-all group text-left"
          >
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center text-blue-400">
                <FileText className="w-5 h-5" />
              </div>
              <div>
                <span className="text-sm font-bold text-slate-100 group-hover:text-blue-300 transition-colors block">
                  Raw JSON Telemetry
                </span>
                <span className="text-xs text-slate-400">
                  Full CFG graphs, SMT constraints, and execution trace states
                </span>
              </div>
            </div>
            <Download className="w-4 h-4 text-slate-400 group-hover:text-blue-400" />
          </button>
        </div>
      </div>
    </div>
  );
};
