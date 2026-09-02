import React, { useState } from 'react';

export type StickerVariant = 'holographic' | 'hazard' | 'smt' | 'secure' | 'cyber' | 'warning' | 'glass';

interface HoloStickerProps {
  label: string;
  sublabel?: string;
  icon?: React.ReactNode;
  variant?: StickerVariant;
  rotation?: number; // degrees, e.g. -4 or 6
  floatDelay?: number; // seconds
  floatAnimation?: 'gentle' | 'tilt' | 'orbit' | 'none';
  className?: string;
  onClick?: () => void;
}

export const HoloSticker: React.FC<HoloStickerProps> = ({
  label,
  sublabel,
  icon,
  variant = 'holographic',
  rotation = 0,
  floatDelay = 0,
  floatAnimation = 'gentle',
  className = '',
  onClick,
}) => {
  const [isHovered, setIsHovered] = useState(false);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = (e.clientX - rect.left) / rect.width - 0.5;
    const y = (e.clientY - rect.top) / rect.height - 0.5;
    setMousePos({ x, y });
  };

  const getVariantClass = () => {
    switch (variant) {
      case 'holographic':
        return 'sticker-holographic';
      case 'hazard':
        return 'sticker-hazard';
      case 'smt':
        return 'sticker-smt';
      case 'secure':
        return 'sticker-secure';
      case 'cyber':
        return 'bg-gradient-to-r from-cyan-950/80 to-blue-950/80 border border-cyan-400/50 text-cyan-200 shadow-lg shadow-cyan-500/20';
      case 'warning':
        return 'bg-gradient-to-r from-red-950/80 to-amber-950/80 border border-red-500/50 text-red-200 shadow-lg shadow-red-500/20';
      case 'glass':
      default:
        return 'bg-slate-900/80 border border-slate-700/60 text-slate-200 shadow-xl';
    }
  };

  const getFloatClass = () => {
    switch (floatAnimation) {
      case 'gentle':
        return 'animate-float-gentle';
      case 'tilt':
        return 'animate-float-tilt';
      case 'orbit':
        return 'animate-float-orbit';
      case 'none':
      default:
        return '';
    }
  };

  // Dynamic 3D tilt transformation
  const tiltStyle: React.CSSProperties = {
    '--sticker-rot': `${rotation}deg`,
    animationDelay: `${floatDelay}s`,
    transform: isHovered
      ? `perspective(800px) rotateX(${-mousePos.y * 24}deg) rotateY(${mousePos.x * 24}deg) scale3d(1.1, 1.1, 1.1) rotate(${rotation}deg)`
      : `rotate(${rotation}deg)`,
  } as React.CSSProperties;

  return (
    <div
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => {
        setIsHovered(false);
        setMousePos({ x: 0, y: 0 });
      }}
      onMouseMove={handleMouseMove}
      onClick={onClick}
      style={tiltStyle}
      className={`sticker-badge ${getVariantClass()} ${getFloatClass()} ${className}`}
    >
      {icon && <span className="inline-flex items-center text-sm">{icon}</span>}
      <div className="flex flex-col text-left leading-tight">
        <span>{label}</span>
        {sublabel && (
          <span className="text-[9px] font-mono tracking-widest opacity-80 uppercase">
            {sublabel}
          </span>
        )}
      </div>
    </div>
  );
};

// HoloSticker v2: improved 3D perspective tilt on hover with spring easing
