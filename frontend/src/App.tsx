import React, { useState, useEffect } from 'react';
import { Navbar, type AppTab, type AppRoute } from './components/Navbar';
import { LandingPage } from './components/LandingPage';
import { FileUpload } from './components/FileUpload';
import { LiveConsole } from './components/LiveConsole';
import { GraphViewer } from './components/GraphViewer';
import { TraceStepper } from './components/TraceStepper';
import { VulnerabilityDashboard } from './components/VulnerabilityDashboard';
import { ExportModal } from './components/ExportModal';
import { LoginForm } from './components/auth/LoginForm';
import { SignupForm } from './components/auth/SignupForm';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
import type { SampleBinary, AnalysisJob } from './types';
import { Activity, Network, ShieldAlert, FileText, Terminal, ArrowLeft } from 'lucide-react';
import { cn } from './lib/cn';
import { BRAND } from './config/brand';

const AppContent: React.FC = () => {
  const [currentRoute, setCurrentRoute] = useState<AppRoute>('home');
  const [activeTab, setActiveTab] = useState<AppTab>('intake');
  const [apiOnline, setApiOnline] = useState<boolean>(true);
  const [samples, setSamples] = useState<SampleBinary[]>([]);
  const [analysisJob, setAnalysisJob] = useState<AnalysisJob | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [currentTraceStep, setCurrentTraceStep] = useState<number>(0);
  const [activeNodeId, setActiveNodeId] = useState<string | undefined>();
  const [workbenchView, setWorkbenchView] = useState<'vulns' | 'graph' | 'trace'>('vulns');
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const res = await fetch('/api/health');
        setApiOnline(res.ok);
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
              setWorkbenchView('vulns');
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

  useEffect(() => {
    if (analysisJob?.trace && analysisJob.trace[currentTraceStep]) {
      const step = analysisJob.trace[currentTraceStep];
      setActiveNodeId(step.instruction_address || step.basic_block);
    }
  }, [currentTraceStep, analysisJob?.trace]);

  const handleStartAnalysis = async (config: {
    token?: string;
    sampleId?: string;
    maxSteps: number;
    symbolicSize: number;
    enableGnn: boolean;
  }) => {
    setIsAnalyzing(true);
    setCurrentRoute('workspace');
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
    } catch (e) {
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
    setCurrentRoute('workspace');
    setActiveTab('intake');
  };

  // Route 1: Sign In
  if (currentRoute === 'login') {
    return (
      <LoginForm
        onSuccess={() => {
          setCurrentRoute('workspace');
          setActiveTab('intake');
        }}
        onNavigateToSignup={() => setCurrentRoute('signup')}
        onBackToHome={() => setCurrentRoute('home')}
      />
    );
  }

  // Route 2: Register
  if (currentRoute === 'signup') {
    return (
      <SignupForm
        onSuccess={() => {
          setCurrentRoute('workspace');
          setActiveTab('intake');
        }}
        onNavigateToLogin={() => setCurrentRoute('login')}
        onBackToHome={() => setCurrentRoute('home')}
      />
    );
  }

  return (
    <div className="relative flex min-h-screen flex-col bg-canvas text-primary selection:bg-rose-500/25">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        currentRoute={currentRoute}
        setCurrentRoute={setCurrentRoute}
        apiOnline={apiOnline}
        hasAnalysisResults={Boolean(analysisJob && analysisJob.status === 'completed')}
        isAnalyzing={isAnalyzing}
        onNewScan={handleResetNewScan}
      />

      {currentRoute === 'home' ? (
        <main className="relative z-10 flex-1">
          <LandingPage
            onStartIntake={() => {
              setCurrentRoute('workspace');
              setActiveTab('intake');
            }}
            onSelectSample={handleSelectSampleAndLaunch}
            samples={samples}
          />
        </main>
      ) : (
        /* Workspace Environment */
        <main className="relative z-10 flex-1 pb-16">
          {/* Workspace Subheader Navigation */}
          <div className="border-b border-border bg-surface/50 backdrop-blur-sm">
            <div className="mx-auto max-w-7xl px-4 py-3 sm:px-6 lg:px-8 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => setCurrentRoute('home')}
                  className="flex items-center gap-1.5 text-xs font-mono text-secondary hover:text-primary transition-colors"
                >
                  <ArrowLeft className="h-3.5 w-3.5" />
                  <span>Exit to {BRAND.name}</span>
                </button>
                <span className="text-border">|</span>
                <span className="text-xs font-mono text-secondary">
                  Target:{' '}
                  <strong className="text-primary font-semibold">
                    {analysisJob?.binary_info?.filename || 'No target selected'}
                  </strong>
                </span>
              </div>

              {/* Segmented Workspace Tabs */}
              <div className="inline-flex rounded-lg border border-border bg-surface p-1">
                {[
                  { id: 'intake' as const, label: 'Intake Target', icon: FileText },
                  { id: 'analysis' as const, label: 'Engine Console', icon: Terminal },
                  {
                    id: 'dashboard' as const,
                    label: 'Findings Workbench',
                    icon: Activity,
                    disabled: !analysisJob || analysisJob.status !== 'completed',
                  },
                ].map((t) => {
                  const on = activeTab === t.id;
                  const Icon = t.icon;
                  return (
                    <button
                      key={t.id}
                      type="button"
                      disabled={t.disabled}
                      onClick={() => setActiveTab(t.id)}
                      className={cn(
                        'flex items-center gap-2 rounded-md px-3 py-1 font-mono text-xs font-semibold uppercase tracking-wider transition-all',
                        on
                          ? 'bg-surface-raised text-rose-500 dark:text-rose-400 shadow-sm border border-border'
                          : 'text-secondary hover:text-primary hover:bg-surface-raised/40',
                        t.disabled && 'opacity-35 cursor-not-allowed hover:bg-transparent hover:text-secondary'
                      )}
                    >
                      <Icon className="h-3.5 w-3.5" />
                      <span>{t.label}</span>
                      {t.id === 'analysis' && isAnalyzing && (
                        <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Active Workspace View Content */}
          <div className="pt-6">
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
                <div className="mx-auto max-w-7xl px-4 pt-2 sm:px-6 lg:px-8">
                  <div className="inline-flex rounded-lg border border-border bg-surface p-1">
                    {[
                      { id: 'vulns' as const, label: 'Proved Findings', icon: ShieldAlert },
                      { id: 'graph' as const, label: 'VEX CFG / Call Graph', icon: Network },
                      { id: 'trace' as const, label: 'SMT Trace Replay', icon: Activity },
                    ].map((tab) => (
                      <button
                        key={tab.id}
                        type="button"
                        onClick={() => setWorkbenchView(tab.id)}
                        className={cn(
                          'flex items-center gap-2 rounded-md px-3.5 py-1.5 font-mono text-xs font-semibold uppercase tracking-wider transition-all',
                          workbenchView === tab.id
                            ? 'bg-surface-raised text-rose-400 shadow-sm border border-border'
                            : 'text-secondary hover:text-primary hover:bg-surface-raised/40'
                        )}
                      >
                        <tab.icon className="h-3.5 w-3.5" />
                        {tab.label}
                      </button>
                    ))}
                  </div>
                </div>

                {workbenchView === 'vulns' && (
                  <VulnerabilityDashboard
                    vulnerabilities={analysisJob.vulnerabilities || []}
                    mitigations={
                      analysisJob.mitigations || {
                        PIE: false,
                        NX: false,
                        STACK_CANARY: false,
                        FULL_RELRO: false,
                        PARTIAL_RELRO: false,
                        FORTIFY: false,
                      }
                    }
                    metrics={analysisJob.metrics || {}}
                    binaryInfo={analysisJob.binary_info || { filename: 'binary' }}
                    analysisId={analysisJob.id}
                    onOpenExportModal={() => setIsExportModalOpen(true)}
                  />
                )}

                {workbenchView === 'graph' && (
                  <div className="mx-auto max-w-7xl space-y-4 px-4 sm:px-6 lg:px-8">
                    <GraphViewer
                      cfgData={analysisJob.cfg}
                      cgData={analysisJob.cg}
                      activeNodeId={activeNodeId}
                    />
                  </div>
                )}

                {workbenchView === 'trace' && (
                  <div className="mx-auto max-w-5xl space-y-4 px-4 sm:px-6 lg:px-8">
                    <TraceStepper
                      trace={analysisJob.trace || []}
                      currentStep={currentTraceStep}
                      onStepChange={setCurrentTraceStep}
                    />
                  </div>
                )}
              </div>
            )}
          </div>
        </main>
      )}

      <ExportModal
        isOpen={isExportModalOpen}
        onClose={() => setIsExportModalOpen(false)}
        analysisJob={analysisJob}
      />
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
};

export default App;
