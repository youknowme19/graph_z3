import React from 'react';
import { ShieldCheck, Github, BookOpen, Terminal, Activity } from 'lucide-react';

export const CyberFooter: React.FC = () => {
  return (
    <footer className="relative z-10 w-full border-t border-slate-800/80 bg-[#050811] py-12 px-4 sm:px-6 lg:px-8 font-mono text-xs">
      <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400">
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div>
            <div className="font-bold text-slate-200">
              GRAPH_Z3 // NEURO-SYMBOLIC BINARY FUZZER
            </div>
            <div className="text-[11px] text-slate-500 font-sans">
              PyTorch Geometric SageConv GNN + angr Symbolic Execution + Z3 SMT Theorem Prover
            </div>
          </div>
        </div>

        {/* Live Engine Status Strip */}
        <div className="flex flex-wrap items-center gap-3 text-[11px]">
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Z3 Theorem Prover 4.12: READY</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            <span>SageConv GNN: ACTIVE</span>
          </div>
          <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-slate-300">
            <span className="w-2 h-2 rounded-full bg-purple-400" />
            <span>AArch64 + x86_64: SUPPORTED</span>
          </div>
        </div>
      </div>

      <div className="max-w-7xl mx-auto mt-8 pt-6 border-t border-slate-900 flex flex-col sm:flex-row items-center justify-between gap-4 text-[11px] text-slate-500">
        <div>
          MIT License. Built for formal software verification & commercial security audits.
        </div>
        <div className="flex items-center gap-4">
          <a
            href="https://github.com/sandy191020/graph_z3"
            target="_blank"
            rel="noreferrer"
            className="hover:text-cyan-400 transition-colors flex items-center gap-1.5"
          >
            <Github className="w-3.5 h-3.5" />
            <span>GitHub Repository</span>
          </a>
        </div>
      </div>
    </footer>
  );
};
