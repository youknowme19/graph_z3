import React from 'react';
import { Shield, Cpu, Activity, FileText, RefreshCw, Terminal } from 'lucide-react';

export type AppTab = 'landing' | 'intake' | 'analysis' | 'dashboard';

interface NavbarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
  apiOnline: boolean;
  hasAnalysisResults: boolean;
  isAnalyzing: boolean;
  onNewScan: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  apiOnline,
  hasAnalysisResults,
  isAnalyzing,
  onNewScan,
}) => {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-slate-800/80 bg-[#080b11]/80 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
        {/* Brand / Logo */}
        <div
          onClick={() => setActiveTab('landing')}
          className="flex items-center gap-3 cursor-pointer group"
        >
          <div className="relative flex items-center justify-center w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 via-blue-500/10 to-purple-500/20 border border-cyan-500/40 group-hover:border-cyan-400 transition-colors shadow-lg shadow-cyan-500/10">
            <Shield className="w-5 h-5 text-cyan-400 group-hover:scale-110 transition-transform" />
            <div className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-mono font-black tracking-wider text-base text-slate-100 group-hover:text-cyan-300 transition-colors">
                GRAPH_Z3
              </span>
              <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                v2.4
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans tracking-wide">
              Neuro-Symbolic Binary Fuzzer
            </p>
          </div>
        </div>

        {/* Center Stepper / Tabs */}
        <nav className="flex items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('landing')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'landing'
                ? 'bg-slate-800 text-cyan-400 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>Overview</span>
          </button>

          <button
            onClick={() => setActiveTab('intake')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'intake'
                ? 'bg-slate-800 text-cyan-400 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            <span>Intake & Config</span>
          </button>

          <button
            onClick={() => setActiveTab('analysis')}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'analysis'
                ? 'bg-slate-800 text-cyan-400 shadow-sm'
                : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Analysis Console</span>
            {isAnalyzing && (
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            )}
          </button>

          <button
            onClick={() => setActiveTab('dashboard')}
            disabled={!hasAnalysisResults}
            className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
              activeTab === 'dashboard'
                ? 'bg-slate-800 text-cyan-400 shadow-sm'
                : hasAnalysisResults
                ? 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                : 'text-slate-600 cursor-not-allowed opacity-50'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Security Workbench</span>
          </button>
        </nav>

        {/* Right Actions & Health Status */}
        <div className="flex items-center gap-3">
          {/* API Health Pill */}
          <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-[11px] font-mono">
            <span
              className={`w-2 h-2 rounded-full ${
                apiOnline ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-red-500'
              }`}
            />
            <span className={apiOnline ? 'text-emerald-400' : 'text-red-400'}>
              {apiOnline ? 'ENGINE READY' : 'OFFLINE'}
            </span>
          </div>

          {hasAnalysisResults && (
            <button
              onClick={onNewScan}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/80 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>New Target</span>
            </button>
          )}
        </div>
      </div>
    </header>
  );
};
