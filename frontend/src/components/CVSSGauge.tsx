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

  let severityLabel = 'LOW';
  let gradientId = 'cvss-low';
  let startColor = '#7dcca0';
  let endColor = '#d4ff4a';
  let textColor = 'text-safe';
  let badgeBg = 'border-safe/40 text-safe';

  if (normalizedScore >= 9.0) {
    severityLabel = 'CRITICAL';
    gradientId = 'cvss-crit';
    startColor = '#ff3b1f';
    endColor = '#c4a35a';
    textColor = 'text-hazard';
    badgeBg = 'border-hazard/40 text-hazard';
  } else if (normalizedScore >= 7.0) {
    severityLabel = 'HIGH';
    gradientId = 'cvss-high';
    startColor = '#c4a35a';
    endColor = '#ff3b1f';
    textColor = 'text-brass';
    badgeBg = 'border-brass/40 text-brass';
  } else if (normalizedScore >= 4.0) {
    severityLabel = 'MEDIUM';
    gradientId = 'cvss-med';
    startColor = '#c4a35a';
    endColor = '#ebe6dc';
    textColor = 'text-brass';
    badgeBg = 'border-brass/30 text-brass';
  }

  const dim = (radius + strokeWidth) * 2 + 10;
  const vectorParts = vectorString.replace('CVSS:3.1/', '').split('/');

  return (
    <div className={`flex flex-col items-center ${className}`}>
      <div className="relative flex items-center justify-center">
        <svg width={dim} height={dim} className="-rotate-90 transform">
          <defs>
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor={startColor} />
              <stop offset="100%" stopColor={endColor} />
            </linearGradient>
          </defs>
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke="currentColor"
            strokeWidth={strokeWidth}
            className="text-line"
            fill="transparent"
          />
          <circle
            cx={dim / 2}
            cy={dim / 2}
            r={radius}
            stroke={`url(#${gradientId})`}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="butt"
            fill="transparent"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span
            className={`font-mono font-bold ${
              size === 'sm' ? 'text-sm' : size === 'md' ? 'text-2xl' : 'text-4xl'
            } ${textColor}`}
          >
            {normalizedScore.toFixed(1)}
          </span>
          {size !== 'sm' && (
            <span className="text-[10px] tracking-wider text-mute uppercase">CVSS v3.1</span>
          )}
        </div>
      </div>

      <div className="mt-2 flex items-center gap-1.5">
        <span className={`inline-flex items-center gap-1 border px-2 py-0.5 text-xs uppercase ${badgeBg}`}>
          {normalizedScore >= 9.0 ? (
            <ShieldAlert className="h-3 w-3" />
          ) : normalizedScore >= 7.0 ? (
            <AlertTriangle className="h-3 w-3" />
          ) : (
            <ShieldCheck className="h-3 w-3" />
          )}
          {severityLabel}
        </span>
      </div>

      {showVector && (
        <div className="mt-4 w-full">
          <div className="mb-1.5 text-center font-mono text-[11px] text-mute">{vectorString}</div>
          <div className="grid grid-cols-4 gap-1.5 text-center font-mono text-[10px]">
            {vectorParts.map((part) => {
              const [key, val] = part.split(':');
              return (
                <div key={key} className="border border-line bg-ink px-1.5 py-1">
                  <div className="text-mute">{key}</div>
                  <div className="font-bold text-signal">{val}</div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
