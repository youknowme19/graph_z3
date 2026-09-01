import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Search, ArrowDown } from 'lucide-react';
import type { LogEntry } from '../types';

interface LiveConsoleProps {
  logs: LogEntry[];
  isAnalyzing: boolean;
  progress: number;
}

export const LiveConsole: React.FC<LiveConsoleProps> = ({
  logs,
  isAnalyzing,
  progress,
}) => {
  const [filterLevel, setFilterLevel] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [autoScroll, setAutoScroll] = useState<boolean>(true);
  const consoleBottomRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (autoScroll && consoleBottomRef.current) {
      consoleBottomRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  const filteredLogs = logs.filter((log) => {
    if (filterLevel !== 'ALL' && log.level !== filterLevel) return false;
    if (
      searchQuery &&
      !log.msg.toLowerCase().includes(searchQuery.toLowerCase()) &&
      !log.level.toLowerCase().includes(searchQuery.toLowerCase())
    ) {
      return false;
    }
    return true;
  });

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'INIT':
      case 'CONFIG':
        return 'text-cyan-400 bg-cyan-950/40 border-cyan-800/60';
      case 'GRAPH':
        return 'text-blue-400 bg-blue-950/40 border-blue-800/60';
      case 'GNN':
        return 'text-amber-400 bg-amber-950/40 border-amber-800/60';
      case 'SMT':
      case 'STEP':
        return 'text-purple-400 bg-purple-950/40 border-purple-800/60';
      case 'VULN':
      case 'ERROR':
        return 'text-red-400 bg-red-950/40 border-red-800/60 font-bold';
      case 'SUCCESS':
        return 'text-emerald-400 bg-emerald-950/40 border-emerald-800/60';
      case 'WARN':
        return 'text-yellow-400 bg-yellow-950/40 border-yellow-800/60';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-800';
    }
  };

  return (
    <div className="relative z-10 w-full max-w-6xl mx-auto px-4 sm:px-6 py-6 space-y-4">
      {/* Console Header & Filters */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-4 rounded-2xl bg-slate-900/80 border border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
            <Terminal className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                ENGINE TELEMETRY STREAM
              </h3>
              {isAnalyzing && (
                <span className="flex items-center gap-1 text-[10px] font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                  <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                  ANALYZING ({progress}%)
                </span>
              )}
            </div>
            <p className="text-[11px] text-slate-400 font-mono">
              Live stdout/events from angr, PyTorch VulnGNN, and Z3 SMT solver
            </p>
          </div>
        </div>

        {/* Search & Level Filter */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search logs..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none w-36 sm:w-44"
            />
          </div>

          <select
            value={filterLevel}
            onChange={(e) => setFilterLevel(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 font-mono outline-none"
          >
            <option value="ALL">ALL LEVELS</option>
            <option value="VULN">VULN</option>
            <option value="GNN">GNN</option>
            <option value="SMT">SMT</option>
            <option value="GRAPH">GRAPH</option>
            <option value="ERROR">ERROR</option>
          </select>

          <button
            onClick={() => setAutoScroll(!autoScroll)}
            className={`p-1.5 rounded-lg border text-xs transition-colors ${
              autoScroll
                ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                : 'bg-slate-950 border-slate-800 text-slate-400'
            }`}
            title="Toggle Auto-Scroll"
          >
            <ArrowDown className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal Display */}
      <div className="relative rounded-2xl bg-[#06080e] border border-slate-800/90 shadow-2xl p-4 font-mono text-xs overflow-hidden">
        {/* Terminal Titlebar */}
        <div className="flex items-center justify-between border-b border-slate-800/60 pb-3 mb-3 text-[11px] text-slate-400">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
            <span className="ml-2 text-slate-400">session_id: /z3_smt_stream</span>
          </div>
          <span>{filteredLogs.length} events</span>
        </div>

        {/* Log Entries Container */}
        <div className="h-[460px] overflow-y-auto space-y-1.5 pr-2 font-mono">
          {filteredLogs.length === 0 ? (
            <div className="h-full flex items-center justify-center text-slate-400">
              <span>Awaiting solver execution events...</span>
            </div>
          ) : (
            filteredLogs.map((log, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2.5 py-0.5 hover:bg-slate-900/40 rounded px-1 transition-colors leading-relaxed"
              >
                <span className="text-[10px] text-slate-400 select-none flex-shrink-0">
                  {new Date(log.ts * 1000).toISOString().substr(11, 8)}
                </span>
                <span
                  className={`px-1.5 py-0.2 text-[9px] font-bold rounded border uppercase flex-shrink-0 tracking-wider ${getLevelColor(
                    log.level
                  )}`}
                >
                  {log.level}
                </span>
                <span className="text-slate-300 break-all">{log.msg}</span>
              </div>
            ))
          )}
          <div ref={consoleBottomRef} />
        </div>
      </div>
    </div>
  );
};
