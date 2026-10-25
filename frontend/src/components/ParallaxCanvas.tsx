import React from 'react';

/** Minimal ambient background: subtle glow at top, zero visual clutter. */
export const ParallaxCanvas: React.FC = () => {
  return (
    <div className="pointer-events-none fixed inset-0 z-0 overflow-hidden" aria-hidden>
      {/* Top subtle radial spotlight */}
      <div
        className="absolute top-[-20%] left-1/2 h-[600px] w-[1000px] -translate-x-1/2 rounded-full opacity-25 blur-[120px]"
        style={{
          background: 'radial-gradient(circle, rgba(16, 185, 129, 0.15) 0%, rgba(99, 102, 241, 0.08) 50%, transparent 80%)',
        }}
      />
      {/* Very subtle grid overlay with soft mask */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(to right, #ffffff 1px, transparent 1px), linear-gradient(to bottom, #ffffff 1px, transparent 1px)`,
          backgroundSize: '48px 48px',
          maskImage: 'radial-gradient(ellipse at center top, black 30%, transparent 80%)',
          WebkitMaskImage: 'radial-gradient(ellipse at center top, black 30%, transparent 80%)',
        }}
      />
    </div>
  );
};
