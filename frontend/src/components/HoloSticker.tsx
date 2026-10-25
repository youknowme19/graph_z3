import React from 'react';
import { cn } from '../lib/cn';

export type StickerVariant = 'holographic' | 'hazard' | 'smt' | 'secure' | 'cyber' | 'warning' | 'glass';

interface HoloStickerProps {
  label: string;
  sublabel?: string;
  icon?: React.ReactNode;
  variant?: StickerVariant;
  rotation?: number;
  floatDelay?: number;
  floatAnimation?: 'gentle' | 'tilt' | 'orbit' | 'none';
  className?: string;
  onClick?: () => void;
}

const VARIANT_RULE: Record<StickerVariant, string> = {
  holographic: 'text-brass border-brass/40',
  hazard: 'text-hazard border-hazard/50',
  smt: 'text-signal border-signal/40',
  secure: 'text-safe border-safe/40',
  cyber: 'text-paper border-line-strong',
  warning: 'text-hazard border-hazard/50',
  glass: 'text-paper-dim border-line',
};

/** Editorial chapter mark — keeps the existing HoloSticker contract. */
export const HoloSticker: React.FC<HoloStickerProps> = ({
  label,
  sublabel,
  icon,
  variant = 'holographic',
  className = '',
  onClick,
}) => {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      className={cn(
        'inline-flex items-center gap-2.5 border bg-ink-2/80 px-3 py-1.5 text-left',
        VARIANT_RULE[variant],
        className,
      )}
    >
      {icon && <span className="inline-flex shrink-0 opacity-80">{icon}</span>}
      <span className="flex flex-col leading-tight">
        <span className="font-mono text-[10px] font-semibold uppercase tracking-[0.18em]">{label}</span>
        {sublabel && (
          <span className="mt-0.5 font-sans text-[11px] font-normal normal-case tracking-normal text-mute">
            {sublabel}
          </span>
        )}
      </span>
    </Tag>
  );
};
