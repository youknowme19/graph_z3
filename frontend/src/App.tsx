import React, { useState, useEffect } from 'react';
import { Navbar, type AppTab } from './components/Navbar';
import { ParallaxCanvas } from './components/ParallaxCanvas';
import { LandingPage } from './components/LandingPage';
import { FileUpload } from './components/FileUpload';
import { LiveConsole } from './components/LiveConsole';
import { GraphViewer } from './components/GraphViewer';
import { TraceStepper } from './components/TraceStepper';
import { VulnerabilityDashboard } from './components/VulnerabilityDashboard';
import { ExportModal } from './components/ExportModal';
import type { SampleBinary, AnalysisJob } from './types';
import { ShieldAlert, Activity, Network } from 'lucide-react';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<AppTab>('landing');
  const [apiOnline, setApiOnline] = useState<boolean>(true);
  const [samples, setSamples] = useState<SampleBinary[]>([]);
  const [analysisJob, setAnalysisJob] = useState<AnalysisJob | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [currentTraceStep, setCurrentTraceStep] = useState<number>(0);
  const [activeNodeId, setActiveNodeId] = useState<string | undefined>();
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [workbenchView, setWorkbenchView] = useState<'vulns' | 'graph' | 'trace'>('vulns');

  // Check health and load samples on mount
  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/health');
        if (res.ok) {
          setApiOnline(true);
        } else {
          setApiOnline(false);
        }
      } catch {
        setApiOnline(false);
      }
    };

    const fetchSamples = async () => {
      try {
        const res = await fetch('/api/samples');
        if (res.ok) {
          const data = await res.json();
          setSamples(data.samples || []);
        }
      } catch (e) {
        console.error('Failed to load samples', e);
      }
    };

    checkHealth();
    fetchSamples();
    const interval = setInterval(checkHealth, 8000);
    return () => clearInterval(interval);
  }, []);

  // Poll analysis job status when active
  useEffect(() => {
    if (!analysisJob?.id || !isAnalyzing) return;

    const pollStatus = async () => {
      try {
        const res = await fetch(`/api/status/${analysisJob.id}`);
        if (res.ok) {
          const data: AnalysisJob = await res.json();
          setAnalysisJob(data);

          if (data.status === 'completed' || data.status === 'failed') {
            setIsAnalyzing(false);
            if (data.status === 'completed') {
              setActiveTab('dashboard');
            }
          }
        }
      } catch (err) {
        console.error('Status poll error:', err);
      }
    };

    const interval = setInterval(pollStatus, 1200);
    return () => clearInterval(interval);
  }, [analysisJob?.id, isAnalyzing]);

  // Sync active node in graph with current trace step
  useEffect(() => {
    if (analysisJob?.trace && analysisJob.trace[currentTraceStep]) {
      const step = analysisJob.trace[currentTraceStep];
      setActiveNodeId(step.instruction_address || step.basic_block);
    }
  }, [currentTraceStep, analysisJob?.trace]);

  // Trigger new analysis
  const handleStartAnalysis = async (config: {
    token?: string;
    sampleId?: string;
    maxSteps: number;
    symbolicSize: number;
    enableGnn: boolean;
  }) => {
    setIsAnalyzing(true);
    setActiveTab('analysis');

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          token: config.token,
          sample_id: config.sampleId,
          max_steps: config.maxSteps,
          symbolic_size: config.symbolicSize,
          enable_gnn: config.enableGnn,
        }),
      });

      if (!res.ok) {
        throw new Error(`Engine error: ${res.status}`);
      }

      const data = await res.json();
      setAnalysisJob({
        id: data.analysis_id,
        status: 'running',
        progress: 10,
        logs: [{ ts: Date.now() / 1000, level: 'INIT', msg: 'Job submitted to symbolic fuzzer engine' }],
        metrics: {},
        cfg: { nodes: [], edges: [] },
        cg: { nodes: [], edges: [] },
        trace: [],
        vulnerabilities: [],
        mitigations: {
          PIE: false,
          NX: false,
          STACK_CANARY: false,
          FULL_RELRO: false,
          PARTIAL_RELRO: false,
          FORTIFY: false,
        },
        binary_info: { filename: config.sampleId ? `sample_${config.sampleId}.bin` : 'target_binary' },
      });
      setCurrentTraceStep(0);
    } catch (e: any) {
      console.error(e);
      setIsAnalyzing(false);
    }
  };

  const handleSelectSampleAndLaunch = (sampleId: string) => {
    handleStartAnalysis({
      sampleId,
      maxSteps: 300,
      symbolicSize: 32,
      enableGnn: true,
    });
  };

  const handleResetNewScan = () => {
    setAnalysisJob(null);
    setIsAnalyzing(false);
    setActiveTab('intake');
  };

  return (
    <div className="relative min-h-screen bg-[#080b11] text-[#e2e8f0] flex flex-col selection:bg-cyan-500/20 selection:text-cyan-300">
      {/* Interactive Cyber Particle Canvas */}
      <ParallaxCanvas />

      {/* Navigation Bar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        apiOnline={apiOnline}
        hasAnalysisResults={Boolean(analysisJob && analysisJob.status === 'completed')}
        isAnalyzing={isAnalyzing}
        onNewScan={handleResetNewScan}
      />

      {/* Main Content Area */}
      <main className="flex-1 pb-16">
        {activeTab === 'landing' && (
          <LandingPage
            onStartIntake={() => setActiveTab('intake')}
            onSelectSample={handleSelectSampleAndLaunch}
            samples={samples}
          />
        )}

        {activeTab === 'intake' && (
          <FileUpload
            onStartAnalysis={handleStartAnalysis}
            samples={samples}
            isUploading={isAnalyzing}
          />
        )}

        {activeTab === 'analysis' && (
          <LiveConsole
            logs={analysisJob?.logs || []}
            isAnalyzing={isAnalyzing}
            progress={analysisJob?.progress || 0}
          />
        )}

        {activeTab === 'dashboard' && analysisJob && (
          <div className="space-y-6">
            {/* Sub-view Switcher */}
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-4">
              <div className="flex items-center gap-2 p-1 rounded-xl bg-slate-900/80 border border-slate-800 w-fit">
                <button
                  onClick={() => setWorkbenchView('vulns')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                    workbenchView === 'vulns'
                      ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Vulnerabilities & CVSS</span>
                </button>

                <button
                  onClick={() => setWorkbenchView('graph')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                    workbenchView === 'graph'
                      ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>Interactive CFG / Call Graph</span>
                </button>

                <button
                  onClick={() => setWorkbenchView('trace')}
                  className={`flex items-center gap-2 px-3.5 py-1.5 rounded-lg text-xs font-mono font-bold transition-all ${
                    workbenchView === 'trace'
                      ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  <Activity className="w-3.5 h-3.5" />
                  <span>Trace Stepper & SMT Proofs</span>
                </button>
              </div>
            </div>

            {workbenchView === 'vulns' && (
              <VulnerabilityDashboard
                vulnerabilities={analysisJob.vulnerabilities || []}
                mitigations={analysisJob.mitigations || {
                  PIE: false,
                  NX: false,
                  STACK_CANARY: false,
                  FULL_RELRO: false,
                  PARTIAL_RELRO: false,
                  FORTIFY: false,
                }}
                metrics={analysisJob.metrics || {}}
                binaryInfo={analysisJob.binary_info || { filename: 'binary' }}
                analysisId={analysisJob.id}
                onOpenExportModal={() => setIsExportModalOpen(true)}
              />
            )}

            {workbenchView === 'graph' && (
              <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 space-y-4">
                <GraphViewer
                  cfgData={analysisJob.cfg}
                  cgData={analysisJob.cg}
                  activeNodeId={activeNodeId}
                />
              </div>
            )}

            {workbenchView === 'trace' && (
              <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 space-y-4">
                <TraceStepper
                  trace={analysisJob.trace || []}
                  currentStep={currentTraceStep}
                  onStepChange={setCurrentTraceStep}
                />
              </div>
            )}
          </div>
        )}
      </main>

      {/* Export Reports Modal */}
      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        analysisJob={analysisJob}
      />
    </div>
  );
};

export default App;
