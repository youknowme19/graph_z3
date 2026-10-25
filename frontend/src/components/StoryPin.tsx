import React from 'react';

interface StoryPinProps {
  children: React.ReactNode;
  className?: string;
}

/** Desktop: pinned viewport chapter. Mobile: ordinary flow, no empty sticky space. */
export const StoryPin: React.FC<StoryPinProps> = ({ children, className = '' }) => {
  return (
    <div className={`relative md:h-[165vh] ${className}`}>
      <div className="md:sticky md:top-[var(--nav-h)] md:flex md:h-[calc(100svh-var(--nav-h))] md:flex-col md:overflow-hidden">
        {children}
      </div>
    </div>
  );
};
