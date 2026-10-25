import React, { useEffect, useState } from 'react';
import { cn } from '../lib/cn';

const CHAPTERS = [
  { id: 'act-open', label: '01 Open' },
  { id: 'act-crisis', label: '02 Crisis' },
  { id: 'act-engine', label: '03 Engine' },
  { id: 'act-cfg', label: '04 CFG' },
  { id: 'act-smt', label: '05 SMT' },
  { id: 'act-payload', label: '06 Payload' },
  { id: 'act-fix', label: '07 Fix' },
  { id: 'act-bench', label: '08 Bench' },
  { id: 'act-run', label: '09 Run' },
];

export const ChapterRail: React.FC = () => {
  const [active, setActive] = useState(CHAPTERS[0].id);
  const [progress, setProgress] = useState(0);

  useEffect(() => {
    const onScroll = () => {
      const doc = document.documentElement;
      const max = Math.max(1, doc.scrollHeight - window.innerHeight);
      setProgress(window.scrollY / max);

      let current = CHAPTERS[0].id;
      for (const ch of CHAPTERS) {
        const el = document.getElementById(ch.id);
        if (!el) continue;
        const top = el.getBoundingClientRect().top;
        if (top < window.innerHeight * 0.45) current = ch.id;
      }
      setActive(current);
    };

    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  return (
    <aside
      className="pointer-events-none fixed right-4 top-1/2 z-40 hidden -translate-y-1/2 lg:block"
      aria-label="Chapter navigation"
    >
      <div className="pointer-events-auto flex flex-col items-end gap-1">
        <div className="mb-2 h-16 w-px self-center bg-line-strong">
          <div className="w-px bg-signal" style={{ height: `${Math.round(progress * 100)}%` }} />
        </div>
        {CHAPTERS.map((ch) => (
          <a
            key={ch.id}
            href={`#${ch.id}`}
            className={cn(
              'font-mono text-[10px] tracking-[0.14em] uppercase transition-colors',
              active === ch.id ? 'text-signal' : 'text-mute hover:text-paper-dim',
            )}
          >
            {ch.label}
          </a>
        ))}
      </div>
    </aside>
  );
};
