import React, { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
// @ts-ignore
import dagre from 'cytoscape-dagre';
import {
  Maximize2,
  ZoomIn,
  ZoomOut,
  RotateCcw,
  Search,
  Code2,
  Flame,
} from 'lucide-react';
import type { GraphData, GraphNode } from '../types';

cytoscape.use(dagre);

interface GraphViewerProps {
  cfgData: GraphData;
  cgData: GraphData;
  activeNodeId?: string;
  onNodeSelect?: (node: GraphNode['data']) => void;
}

export const GraphViewer: React.FC<GraphViewerProps> = ({
  cfgData,
  cgData,
  activeNodeId,
  onNodeSelect,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [graphType, setGraphType] = useState<'cfg' | 'cg'>('cfg');
  const [layoutName, setLayoutName] = useState<string>('dagre');
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const currentData = graphType === 'cfg' ? cfgData : cgData;

  // Initialize and update Cytoscape instance
  useEffect(() => {
    if (!containerRef.current) return;

    const elements: cytoscape.ElementDefinition[] = [];

    // Transform nodes
    currentData.nodes.forEach((node) => {
      elements.push({
        group: 'nodes',
        data: {
          ...node.data,
          id: String(node.data.id),
          label: String(node.data.label || node.data.name || node.data.id),
        },
        classes: node.classes || '',
      });
    });

    // Transform edges
    currentData.edges.forEach((edge) => {
      elements.push({
        group: 'edges',
        data: {
          ...edge.data,
          id: String(edge.data.id || `${edge.data.source}->${edge.data.target}`),
          source: String(edge.data.source),
          target: String(edge.data.target),
        },
        classes: edge.classes || '',
      });
    });

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            color: '#cbd5e1',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': '10px',
            'font-weight': 600,
            'text-valign': 'center',
            'text-halign': 'center',
            'text-wrap': 'wrap',
            'text-max-width': '140px',
            width: 'label',
            height: 'label',
            padding: '10px 14px',
            shape: 'round-rectangle',
            'background-color': '#0d1322',
            'border-width': 1.5,
            'border-color': '#1e293b',
          },
        },
        {
          selector: '.entry',
          style: {
            'border-color': '#10b981',
            'border-width': 2.5,
            color: '#34d399',
            'background-color': '#06231a',
            shape: 'diamond',
          },
        },
        {
          selector: '.library',
          style: {
            'border-color': '#a855f7',
            'border-width': 1.5,
            color: '#c084fc',
            'background-color': '#1a0d2e',
            shape: 'round-rectangle',
          },
        },
        {
          selector: '.loop-header',
          style: {
            'border-color': '#06b6d4',
            'border-style': 'dashed',
            'border-width': 2.5,
            'background-color': '#06202e',
          },
        },
        {
          selector: '.gnn-vulnerable-node',
          style: {
            'border-color': '#f97316',
            'border-width': 2.5,
            color: '#fdba74',
            'background-color': '#301306',
          },
        },
        {
          selector: '.active-node',
          style: {
            'border-color': '#ef4444',
            'border-width': 3,
            color: '#fca5a5',
            'background-color': '#450a0a',
            'z-index': 999,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-color': '#38bdf8',
            'border-width': 3,
            'background-color': '#082f49',
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.8,
            'line-color': '#334155',
            'target-arrow-color': '#334155',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.9,
            opacity: 0.8,
          },
        },
        {
          selector: '.active-edge',
          style: {
            width: 3,
            'line-color': '#ef4444',
            'target-arrow-color': '#ef4444',
            'line-style': 'dashed',
            opacity: 1,
            'z-index': 999,
          },
        },
      ],
      layout: {
        name: layoutName === 'dagre' ? 'dagre' : layoutName,
        rankDir: 'TB',
        nodeSep: 60,
        rankSep: 90,
        padding: 40,
        animate: true,
        animationDuration: 300,
      } as any,
    });

    cy.on('tap', 'node', (evt) => {
      const node = evt.target;
      setSelectedNodeData(node.data());
      if (onNodeSelect) {
        onNodeSelect(node.data());
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
    };
  }, [currentData, layoutName, onNodeSelect]);

  // Highlight active node during trace replay
  useEffect(() => {
    if (!cyRef.current) return;
    cyRef.current.nodes().removeClass('active-node');
    if (activeNodeId) {
      const target = cyRef.current.getElementById(String(activeNodeId));
      if (target.length > 0) {
        target.addClass('active-node');
      }
    }
  }, [activeNodeId]);

  // Search handler
  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!cyRef.current || !searchQuery) return;
    const found = cyRef.current.nodes().filter((node) => {
      const lbl = String(node.data('label') || '').toLowerCase();
      const id = String(node.data('id') || '').toLowerCase();
      const name = String(node.data('name') || '').toLowerCase();
      return (
        lbl.includes(searchQuery.toLowerCase()) ||
        id.includes(searchQuery.toLowerCase()) ||
        name.includes(searchQuery.toLowerCase())
      );
    });
    if (found.length > 0) {
      cyRef.current.center(found);
      cyRef.current.zoom(1.3);
      found.select();
      setSelectedNodeData(found.first().data());
    }
  };

  const handleZoomIn = () => cyRef.current?.zoom((cyRef.current.zoom() || 1) * 1.25);
  const handleZoomOut = () => cyRef.current?.zoom((cyRef.current.zoom() || 1) * 0.8);
  const handleFit = () => cyRef.current?.fit(undefined, 40);
  const handleReset = () => {
    cyRef.current?.fit();
    cyRef.current?.zoom(1);
  };

  return (
    <div className="relative w-full h-[640px] rounded-2xl bg-[#06080e] border border-slate-800/90 shadow-2xl flex flex-col overflow-hidden">
      {/* Top Controls Toolbar */}
      <div className="p-3.5 border-b border-slate-800/80 bg-slate-950/70 backdrop-blur-md flex flex-wrap items-center justify-between gap-3 z-10">
        {/* Graph Mode Toggles */}
        <div className="flex items-center gap-1.5 bg-slate-900/90 p-1 rounded-xl border border-slate-800">
          <button
            onClick={() => setGraphType('cfg')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
              graphType === 'cfg'
                ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Control Flow Graph (CFG)
          </button>
          <button
            onClick={() => setGraphType('cg')}
            className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
              graphType === 'cg'
                ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Call Graph (CG)
          </button>
        </div>

        {/* Layout Switcher & Search */}
        <div className="flex items-center gap-2">
          <select
            value={layoutName}
            onChange={(e) => setLayoutName(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 font-mono outline-none"
          >
            <option value="dagre">Hierarchical (Dagre)</option>
            <option value="cose">Force-Directed (CoSE)</option>
            <option value="concentric">Concentric Circles</option>
            <option value="circle">Circular Ring</option>
            <option value="breadthfirst">Breadth-First Tree</option>
          </select>

          <form onSubmit={handleSearch} className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search function / address..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 font-mono focus:border-cyan-500 outline-none w-44 sm:w-52"
            />
          </form>

          {/* Zoom Buttons */}
          <div className="flex items-center gap-1 bg-slate-900 p-1 rounded-lg border border-slate-800">
            <button
              onClick={handleZoomIn}
              className="p-1.5 text-slate-400 hover:text-cyan-400"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleZoomOut}
              className="p-1.5 text-slate-400 hover:text-cyan-400"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleFit}
              className="p-1.5 text-slate-400 hover:text-cyan-400"
              title="Fit to Screen"
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={handleReset}
              className="p-1.5 text-slate-400 hover:text-cyan-400"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Graph Canvas Area with Split Drawer */}
      <div className="relative flex-1 w-full h-full flex">
        {/* Cytoscape Container */}
        <div ref={containerRef} className="flex-1 w-full h-full bg-[#080b11]" />

        {/* Legend Overlay */}
        <div className="absolute bottom-4 left-4 p-3.5 rounded-xl bg-slate-950/85 backdrop-blur-md border border-slate-800 font-mono text-[10px] space-y-2 shadow-xl pointer-events-none">
          <div className="text-slate-400 font-bold uppercase tracking-wider mb-1">
            Graph Legend
          </div>
          <div className="flex items-center gap-2 text-emerald-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500/20 border border-emerald-400" />
            <span>Entry Function / Block</span>
          </div>
          <div className="flex items-center gap-2 text-cyan-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500/20 border border-dashed border-cyan-400" />
            <span>Loop Header SCC</span>
          </div>
          <div className="flex items-center gap-2 text-amber-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-amber-500/20 border border-amber-400" />
            <span>GNN High-Risk Block</span>
          </div>
          <div className="flex items-center gap-2 text-purple-400">
            <span className="w-2.5 h-2.5 rounded-sm bg-purple-500/20 border border-purple-400" />
            <span>Library / PLT Stub</span>
          </div>
        </div>

        {/* Node Inspector Drawer */}
        {selectedNodeData && (
          <div className="w-84 border-l border-slate-800 bg-slate-950/95 backdrop-blur-md p-4 overflow-y-auto space-y-4 font-mono text-xs z-20">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-cyan-400 font-bold flex items-center gap-1.5">
                <Code2 className="w-4 h-4" />
                BLOCK DISASSEMBLY
              </span>
              <button
                onClick={() => setSelectedNodeData(null)}
                className="text-slate-400 hover:text-slate-200 text-base"
              >
                &times;
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <span className="text-slate-400 text-[10px] uppercase block">
                  Symbol / Function Name
                </span>
                <span className="text-cyan-300 font-bold break-all text-sm">
                  {selectedNodeData.name || selectedNodeData.label || selectedNodeData.id}
                </span>
              </div>

              <div>
                <span className="text-slate-400 text-[10px] uppercase block">
                  Virtual Address
                </span>
                <span className="text-slate-200 font-bold">
                  {selectedNodeData.addr || selectedNodeData.id}
                </span>
              </div>

              {selectedNodeData.gnn_predicted_vulnerable && (
                <div className="p-2.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[11px] flex items-center gap-2">
                  <Flame className="w-4 h-4 text-amber-400 flex-shrink-0" />
                  <span>Flagged High-Risk by SageConv GNN</span>
                </div>
              )}

              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-400 text-[9px] uppercase block">Complexity</span>
                  <span className="text-cyan-400 font-bold">
                    {selectedNodeData.cyclomatic_complexity || 1}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-900 border border-slate-800">
                  <span className="text-slate-400 text-[9px] uppercase block">Instructions</span>
                  <span className="text-slate-200 font-bold">
                    {selectedNodeData.instruction_count || (selectedNodeData.disasm ? selectedNodeData.disasm.length : 1)}
                  </span>
                </div>
              </div>

              {/* Disassembly Snippet */}
              {selectedNodeData.disasm && selectedNodeData.disasm.length > 0 ? (
                <div className="space-y-1.5">
                  <span className="text-slate-400 text-[10px] uppercase block font-bold">
                    Instruction Disassembly
                  </span>
                  <pre className="p-3 rounded-xl bg-[#06080e] border border-slate-800 text-[10px] text-cyan-300 overflow-x-auto max-h-56 leading-relaxed">
                    {selectedNodeData.disasm.join('\n')}
                  </pre>
                </div>
              ) : (
                <div className="p-3 rounded bg-slate-900/60 border border-slate-800 text-slate-400 text-[10px]">
                  Basic block disassembly mapped to symbol table.
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
