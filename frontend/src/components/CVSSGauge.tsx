import React from 'react';
import { ShieldAlert, AlertTriangle, ShieldCheck } from 'lucide-react';

interface CVSSGaugeProps {
  score: number;
  size?: 'sm' | 'md' | 'lg';
  showVector?: boolean;
  vectorString?: string;
  className?: string;
}

export const CVSSGauge: React.FC<CVSSGaugeProps> = ({
  score,
  size = 'md',
  showVector = false,
  vectorString = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
  className = '',
}) => {
  const normalizedScore = Math.max(0, Math.min(10, score || 0));
  const radius = size === 'sm' ? 24 : size === 'md' ? 42 : 58;
  const strokeWidth = size === 'sm' ? 4 : size === 'md' ? 6 : 8;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (normalizedScore / 10) * circumference;

  // Determine gradient colors and severity text
  let severityLabel = 'LOW';
  let gradientId = 'cvss-low';
  let startColor = '#10b981'; // Emerald
  let endColor = '#06b6d4';   // Cyan
  let textColor = 'text-emerald-400';
  let badgeBg = 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300';
  let glowStyle = 'rgba(16, 185, 129, 0.25)';

  if (normalizedScore >= 9.0) {
    severityLabel = 'CRITICAL';
    gradientId = 'cvss-crit';
    startColor = '#ef4444'; // Crimson
    endColor = '#a855f7';   // Neon Violet
    textColor = 'text-red-400';
    badgeBg = 'bg-red-500/15 border-red-500/40 text-red-300';
    glowStyle = 'rgba(239, 68, 68, 0.4)';
  } else if (normalizedScore >= 7.0) {
    severityLabel = 'HIGH';
    gradientId = 'cvss-high';
    startColor = '#f97316'; // Orange
    endColor = '#ef4444';   // Red
    textColor = 'text-orange-400';
    badgeBg = 'bg-orange-500/15 border-orange-500/40 text-orange-300';
    glowStyle = 'rgba(249, 115, 22, 0.3)';
  } else if (normalizedScore >= 4.0) {
    severityLabel = 'MEDIUM';
    gradientId = 'cvss-med';
    startColor = '#eab308'; // Amber
    endColor = '#f97316';   // Orange
    textColor = 'text-yellow-400';
    badgeBg = 'bg-yellow-500/15 border-yellow-500/30 text-yellow-300';
    glowStyle = 'rgba(234, 179, 8, 0.25)';
  }

  const dim = (radius + strokeWidth) * 2 + 10;

  // Parse CVSS Vector metrics
  const vectorParts = vectorString.replace('CVSS:3.1/', '').split('/');

  return (
    <div className={`flex flex-col items-center ${className}`}>
      <div className="relative flex items-center justify-center">
        <svg
          width={dim}
          height={dim}
          className="transform -rotate-90"
          style={{ filter: `drop-shadow(0 0 10px ${glowStyle})` }}
        >
          <defs>
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={startColor} />
              <stop offset="100%" stopColor={endColor} />
            </linearGradient>
          </defs>

          {/* Background Track */}
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-slate-800/80"
            fill="transparent"
          />

          {/* Progress Gradient Arc */}
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke={`url(#${gradientId})`}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Score Readout */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span
            className={`font-mono font-black ${
              size === 'sm' ? 'text-sm' : size === 'md' ? 'text-2xl' : 'text-4xl'
            } ${textColor}`}
          >
            {normalizedScore.toFixed(1)}
          </span>
          {size !== 'sm' && (
            <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">
              CVSS v3.1
            </span>
          )}
        </div>
      </div>

      {/* Severity Badge */}
      <div className="mt-2 flex items-center gap-1.5">
        <span
          className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-semibold uppercase tracking-wider border ${badgeBg}`}
        >
          {normalizedScore >= 9.0 ? (
            <ShieldAlert className="w-3 h-3 text-red-400" />
          ) : normalizedScore >= 7.0 ? (
            <AlertTriangle className="w-3 h-3 text-orange-400" />
          ) : (
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
          )}
          {severityLabel}
        </span>
      </div>

      {/* CVSS v3.1 Vector Breakdown */}
      {showVector && (
        <div className="mt-4 w-full">
          <div className="text-[11px] font-mono text-slate-400 mb-1.5 text-center">
            {vectorString}
          </div>
          <div className="grid grid-cols-4 gap-1.5 text-center text-[10px] font-mono">
            {vectorParts.map((part) => {
              const [key, val] = part.split(':');
              return (
                <div
                  key={key}
                  className="bg-slate-900/80 border border-slate-800 rounded px-1.5 py-1"
                >
                  <div className="text-slate-400 font-semibold">{key}</div>
                  <div className="text-cyan-400 font-bold">{val}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
