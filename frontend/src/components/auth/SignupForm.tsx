import React, { useState } from 'react';
import { Eye, EyeOff, Lock, Mail, ArrowRight, Shield, AlertCircle, CheckCircle2 } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { BRAND } from '../../config/brand';

interface SignupFormProps {
  onSuccess: () => void;
  onNavigateToLogin: () => void;
  onBackToHome: () => void;
}

export const SignupForm: React.FC<SignupFormProps> = ({
  onSuccess,
  onNavigateToLogin,
  onBackToHome,
}) => {
  const { signUp, enterDemoMode, isConfigured } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccessMsg(null);

    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    if (password.length < 6) {
      setError('Password must be at least 6 characters.');
      return;
    }

    setLoading(true);
    const { error: signUpError } = await signUp(email, password);
    setLoading(false);

    if (signUpError) {
      setError(signUpError.message);
    } else {
      setSuccessMsg('Account created successfully! Check your email or sign in.');
      setTimeout(() => {
        onSuccess();
      }, 1500);
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
            Create {BRAND.name} Account
          </h2>
          <p className="text-xs text-zinc-400">
            Initialize an analyst profile for binary analysis
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
              Supabase keys are not set in <code className="font-mono">.env</code>. You can immediately access the full platform using <strong>Guest Analyst Mode</strong> below.
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

        {/* Success Alert */}
        {successMsg && (
          <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-3 text-xs text-emerald-300 flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-400" />
            <span>{successMsg}</span>
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

          <div className="space-y-1.5">
            <label className="block text-xs font-mono uppercase text-zinc-400">
              Confirm Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full rounded-lg border border-zinc-800 bg-zinc-950 py-2.5 pl-10 pr-10 text-xs text-zinc-200 outline-none focus:border-rose-500 transition-colors"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn-signal w-full py-2.5 font-bold"
          >
            <span>{loading ? 'Creating Profile…' : 'Register Account'}</span>
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

        {/* Switch to Login */}
        <div className="text-center text-xs text-zinc-500">
          <span>Already have an account? </span>
          <button
            type="button"
            onClick={onNavigateToLogin}
            className="text-rose-400 font-semibold hover:underline"
          >
            Sign In
          </button>
        </div>
      </div>
    </div>
  );
};
