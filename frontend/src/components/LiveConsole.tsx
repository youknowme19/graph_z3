import React, { useState, useEffect, useRef } from 'react';
import { Terminal, Search, ArrowDown } from 'lucide-react';
import type { LogEntry } from '../types';

interface LiveConsoleProps {
  logs: LogEntry[];
  isAnalyzing: boolean;
  progress: number;
}

export const LiveConsole: React.FC<LiveConsoleProps> = ({ logs, isAnalyzing, progress }) => {
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
        return 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30';
      case 'GRAPH':
        return 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30';
      case 'GNN':
        return 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30';
      case 'SMT':
      case 'STEP':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      case 'VULN':
      case 'ERROR':
        return 'text-rose-400 bg-rose-500/10 border-rose-500/30';
      case 'SUCCESS':
        return 'text-emerald-300 bg-emerald-500/10 border-emerald-500/30';
      case 'WARN':
        return 'text-amber-400 bg-amber-500/10 border-amber-500/30';
      default:
        return 'text-zinc-400 bg-zinc-800 border-zinc-700';
    }
  };

  return (
    <div className="relative z-10 mx-auto w-full max-w-6xl space-y-4 px-4 py-8 sm:px-6">
      {/* Control bar */}
      <div className="flex flex-col justify-between gap-3 rounded-xl border border-zinc-800 bg-zinc-900/60 p-4 sm:flex-row sm:items-center backdrop-blur-sm">
        <div className="flex items-center gap-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-zinc-800 border border-zinc-700/60 text-emerald-400">
            <Terminal className="h-4 w-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-zinc-200">
                Live Engine Console
              </h3>
              {isAnalyzing && (
                <span className="flex items-center gap-1.5 font-mono text-[10px] text-emerald-400 font-bold">
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  Analyzing {progress}%
                </span>
              )}
            </div>
            <p className="font-mono text-[11px] text-zinc-500">angr VEX IR · PyTorch Geometric GraphSAGE · Z3 SMT</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="absolute top-1/2 left-2.5 h-3.5 w-3.5 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              placeholder="Search telemetry…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-36 rounded-md border border-zinc-800 bg-zinc-950 py-1.5 pr-3 pl-8 font-mono text-xs text-zinc-200 outline-none focus:border-emerald-500 sm:w-44"
            />
          </div>

          <select
            value={filterLevel}
            onChange={(e) => setFilterLevel(e.target.value)}
            className="rounded-md border border-zinc-800 bg-zinc-950 px-2.5 py-1.5 font-mono text-xs text-zinc-300 outline-none focus:border-emerald-500"
          >
            <option value="ALL">ALL LEVELS</option>
            <option value="VULN">VULN</option>
            <option value="GNN">GNN</option>
            <option value="SMT">SMT</option>
            <option value="GRAPH">GRAPH</option>
            <option value="ERROR">ERROR</option>
          </select>

          <button
            type="button"
            onClick={() => setAutoScroll(!autoScroll)}
            className={`rounded-md border p-1.5 transition-colors ${
              autoScroll
                ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-400'
                : 'border-zinc-800 bg-zinc-950 text-zinc-500 hover:text-zinc-300'
            }`}
            title="Toggle auto-scroll"
          >
            <ArrowDown className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Terminal log stream window */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-950 p-4 font-mono text-xs shadow-2xl">
        <div className="mb-3 flex items-center justify-between border-b border-zinc-800/80 pb-3 text-[11px] text-zinc-500">
          <span className="flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400" />
            session · z3_smt_stream
          </span>
          <span>{filteredLogs.length} events logged</span>
        </div>

        <div className="h-[460px] space-y-1.5 overflow-y-auto pr-2">
          {filteredLogs.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-zinc-500 space-y-2">
              <Terminal className="h-6 w-6 text-zinc-700" />
              <span>Awaiting solver execution events…</span>
            </div>
          ) : (
            filteredLogs.map((log, idx) => (
              <div key={idx} className="flex items-start gap-2.5 px-1 py-0.5 hover:bg-zinc-900/40 rounded transition-colors">
                <span className="shrink-0 select-none text-[10px] text-zinc-600 font-mono">
                  {new Date(log.ts * 1000).toISOString().substr(11, 8)}
                </span>
                <span className={`shrink-0 rounded px-1.5 py-0.2 font-mono text-[9px] font-bold tracking-wider uppercase border ${getLevelColor(log.level)}`}>
                  {log.level}
                </span>
                <span className="break-all text-zinc-300 leading-relaxed">{log.msg}</span>
              </div>
            ))
          )}
          <div ref={consoleBottomRef} />
        </div>
      </div>
    </div>
  );
};
