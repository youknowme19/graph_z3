import React, { useState } from 'react';
import {
  Activity,
  FileText,
  Menu,
  Terminal,
  X,
  Sun,
  Moon,
  LogOut,
  ArrowRight,
} from 'lucide-react';
import { BRAND } from '../config/brand';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';

export type AppTab = 'landing' | 'intake' | 'analysis' | 'dashboard';
export type AppRoute = 'home' | 'login' | 'signup' | 'workspace';

interface NavbarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
  currentRoute: AppRoute;
  setCurrentRoute: (route: AppRoute) => void;
  apiOnline?: boolean;
  hasAnalysisResults: boolean;
  isAnalyzing: boolean;
  onNewScan: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  currentRoute,
  setCurrentRoute,
  apiOnline: _apiOnline,
  hasAnalysisResults,
  isAnalyzing,
  onNewScan,
}) => {
  const [open, setOpen] = useState(false);
  const { theme, toggleTheme } = useTheme();
  const { user, signOut, isDemoMode } = useAuth();

  const handleNav = (tab: AppTab) => {
    setCurrentRoute('workspace');
    setActiveTab(tab);
    setOpen(false);
  };

  const handleGoHome = () => {
    setCurrentRoute('home');
    setActiveTab('landing');
    setOpen(false);
  };

  return (
    <header className="sticky top-0 z-50 border-b border-border bg-canvas/85 backdrop-blur-md transition-colors">
      <div className="mx-auto flex h-[var(--nav-h)] max-w-7xl items-center justify-between px-4 sm:px-6 lg:px-8">
        {/* Brand Wordmark */}
        <button
          type="button"
          onClick={handleGoHome}
          className="group flex items-center gap-2.5 text-left transition-opacity hover:opacity-90"
        >
          <div className="flex h-7 w-7 items-center justify-center rounded-md bg-rose-500/10 border border-rose-500/30 text-rose-500 font-mono text-xs font-bold shadow-inner">
            V
          </div>
          <div className="flex items-center gap-2">
            <span className="font-extrabold text-sm tracking-tight text-primary">
              {BRAND.wordmark}
            </span>
          </div>
        </button>

        {/* Center Navigation: Clean & focused */}
        {currentRoute !== 'home' && (
          /* Workspace Segmented Tabs */
          <nav className="hidden md:flex items-center gap-1 rounded-lg border border-border bg-surface p-1" aria-label="Workspace Navigation">
            {[
              { id: 'intake' as const, label: 'Scan Intake', icon: FileText },
              { id: 'analysis' as const, label: 'Console', icon: Terminal },
              { id: 'dashboard' as const, label: 'Workbench', icon: Activity, needsResults: true },
            ].map((tab) => {
              const disabled = Boolean(tab.needsResults && !hasAnalysisResults);
              const on = activeTab === tab.id;
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  type="button"
                  disabled={disabled}
                  onClick={() => handleNav(tab.id)}
                  className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition-all ${
                    on
                      ? 'bg-surface-raised text-primary shadow-sm font-semibold'
                      : 'text-secondary hover:text-primary hover:bg-surface-raised/40'
                  } ${disabled ? 'opacity-35 cursor-not-allowed' : ''}`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  <span>{tab.label}</span>
                  {tab.id === 'analysis' && isAnalyzing && (
                    <span className="h-1.5 w-1.5 rounded-full bg-rose-500 animate-pulse" />
                  )}
                </button>
              );
            })}
          </nav>
        )}

        {/* Right Controls */}
        <div className="flex items-center gap-3">

          {/* Theme Toggle Button */}
          <button
            type="button"
            onClick={toggleTheme}
            className="rounded-md border border-border bg-surface p-1.5 text-secondary hover:text-primary transition-colors focus:ring-1 focus:ring-rose-500/40"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
            aria-label={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          >
            {theme === 'dark' ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>

          {/* User Auth state or Sign In/Sign Up */}
          {currentRoute === 'workspace' && hasAnalysisResults && (
            <button
              type="button"
              onClick={onNewScan}
              className="btn-ghost !text-xs !py-1.5 hidden sm:inline-flex"
            >
              <span>New Target</span>
            </button>
          )}

          {user ? (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => {
                  setCurrentRoute('workspace');
                  setActiveTab('intake');
                }}
                className="btn-signal !text-xs !py-1.5 hidden sm:inline-flex"
              >
                <span>Workspace</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>

              <button
                type="button"
                onClick={signOut}
                className="rounded-md border border-border bg-surface p-1.5 text-secondary hover:text-rose-400 transition-colors"
                title={`Sign out (${isDemoMode ? 'Demo Mode' : user.email})`}
              >
                <LogOut className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => setCurrentRoute('login')}
                className="btn-ghost !text-xs !py-1.5"
              >
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setCurrentRoute('workspace');
                  setActiveTab('intake');
                }}
                className="btn-signal !text-xs !py-1.5 hidden sm:inline-flex"
              >
                <span>Get Started</span>
              </button>
            </div>
          )}

          {/* Mobile hamburger */}
          <button
            type="button"
            className="rounded-md border border-border p-1.5 text-secondary hover:text-primary md:hidden"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
            aria-label="Toggle Navigation"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
        </div>
      </div>

      {/* Mobile nav dropdown */}
      {open && (
        <div className="border-t border-border bg-canvas px-4 py-3 md:hidden space-y-2">
          {currentRoute === 'home' ? (
            <div className="flex flex-col space-y-2 py-2">
              <button
                type="button"
                onClick={() => {
                  setCurrentRoute('workspace');
                  setActiveTab('intake');
                  setOpen(false);
                }}
                className="btn-signal w-full py-2.5 text-xs font-semibold"
              >
                Launch Workspace
              </button>
              {!user && (
                <button
                  type="button"
                  onClick={() => {
                    setCurrentRoute('login');
                    setOpen(false);
                  }}
                  className="btn-ghost w-full py-2 text-xs"
                >
                  Sign In
                </button>
              )}
            </div>
          ) : (
            <div className="flex flex-col space-y-1">
              <button
                type="button"
                onClick={handleGoHome}
                className="text-left py-2 text-xs font-medium text-secondary hover:text-primary"
              >
                ← Back to Landing Page
              </button>
              <button
                type="button"
                onClick={() => handleNav('intake')}
                className="text-left py-2 text-xs font-medium text-secondary hover:text-primary"
              >
                Scan Intake
              </button>
              <button
                type="button"
                onClick={() => handleNav('analysis')}
                className="text-left py-2 text-xs font-medium text-secondary hover:text-primary"
              >
                Engine Console
              </button>
              {hasAnalysisResults && (
                <button
                  type="button"
                  onClick={() => handleNav('dashboard')}
                  className="text-left py-2 text-xs font-medium text-secondary hover:text-primary"
                >
                  Findings Workbench
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </header>
  );
};
