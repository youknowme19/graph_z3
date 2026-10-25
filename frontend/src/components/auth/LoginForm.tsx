import React, { useState } from 'react';
import { Eye, EyeOff, Lock, Mail, ArrowRight, Shield, AlertCircle } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { BRAND } from '../../config/brand';

interface LoginFormProps {
  onSuccess: () => void;
  onNavigateToSignup: () => void;
  onBackToHome: () => void;
}

export const LoginForm: React.FC<LoginFormProps> = ({
  onSuccess,
  onNavigateToSignup,
  onBackToHome,
}) => {
  const { signIn, enterDemoMode, isConfigured } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    if (!email || !password) {
      setError('Please provide both email and password.');
      return;
    }

    setLoading(true);
    const { error: signInError } = await signIn(email, password);
    setLoading(false);

    if (signInError) {
      setError(signInError.message);
    } else {
      onSuccess();
    }
  };

  const handleDemoAccess = () => {
    enterDemoMode();
    onSuccess();
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12 bg-canvas">
      <div className="w-full max-w-md space-y-6 card-vanta p-8 shadow-2xl">
        {/* Header */}
        <div className="text-center space-y-2">
          <button
            type="button"
            onClick={onBackToHome}
            className="inline-flex items-center gap-2 font-mono text-xs uppercase tracking-widest text-zinc-500 hover:text-rose-400 transition-colors"
          >
            <span>← Return to {BRAND.name}</span>
          </button>
          <div className="flex justify-center pt-2">
            <div className="h-10 w-10 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-500">
              <Shield className="h-5 w-5" />
            </div>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-zinc-100">
            Sign In to {BRAND.name}
          </h2>
          <p className="text-xs text-zinc-400">
            Access the formal binary verification workspace
          </p>
        </div>

        {/* Supabase Notice if not configured */}
        {!isConfigured && (
          <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-300 space-y-1">
            <div className="flex items-center gap-2 font-semibold">
              <AlertCircle className="h-4 w-4 shrink-0 text-amber-400" />
              <span>Supabase Credentials Notice</span>
            </div>
            <p className="text-[11px] text-amber-200/80 leading-relaxed">
              Environment variables for Supabase are not yet configured in <code className="font-mono">.env</code>. You can immediately access the full platform using <strong>Guest Analyst Mode</strong> below.
            </p>
          </div>
        )}

        {/* Error Alert */}
        {error && (
          <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
            <span>{error}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label className="block text-xs font-mono uppercase text-zinc-400">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@vanta.sec"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-4 text-xs text-zinc-200 outline-none focus:border-rose-500 transition-colors"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="block text-xs font-mono uppercase text-zinc-400">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-10 text-xs text-zinc-200 outline-none focus:border-rose-500 transition-colors"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300"
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-signal w-full py-2.5 font-bold"
          >
            <span>{loading ? 'Authenticating…' : 'Sign In'}</span>
            <ArrowRight className="h-4 w-4" />
          </button>
        </form>

        {/* Guest Demo Mode button */}
        <div className="pt-2 border-t border-zinc-800/80">
          <button
            type="button"
            onClick={handleDemoAccess}
            className="btn-secondary w-full py-2 text-xs font-semibold"
          >
            <span>Continue as Guest Analyst (Demo Mode)</span>
          </button>
        </div>

        {/* Switch to Signup */}
        <div className="text-center text-xs text-zinc-500">
          <span>Need an account? </span>
          <button
            type="button"
            onClick={onNavigateToSignup}
            className="text-rose-400 font-semibold hover:underline"
          >
            Register
          </button>
        </div>
      </div>
    </div>
  );
};
