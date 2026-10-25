import React, { useEffect, useRef, useState } from 'react';
import { StoryPin } from './StoryPin';
import { sectionProgress } from '../lib/motion';

const DIFFS = [
  {
    key: 'overflow',
    label: 'Buffer overflow',
    cwe: 'CWE-121',
    vulnCode: `void handle_packet(char *user_data, size_t user_len) {
    char buffer[16];
    memcpy(buffer, user_data, user_len);
}`,
    fixedCode: `int handle_packet(char *user_data, size_t user_len) {
    char buffer[16];
    if (user_len > sizeof(buffer)) return -EINVAL;
    memcpy(buffer, user_data, user_len);
    return 0;
}`,
    rule: 'Validate buffer bounds before any memory copy.',
    flag: '-fstack-protector-all -D_FORTIFY_SOURCE=2',
  },
  {
    key: 'uaf',
    label: 'Use-after-free',
    cwe: 'CWE-416',
    vulnCode: `void free_session(Session *s) {
    free(s);
    s->status = SESSION_CLOSED;
}`,
    fixedCode: `void free_session(Session **s_ptr) {
    if (!s_ptr || !*s_ptr) return;
    free(*s_ptr);
    *s_ptr = NULL;
}`,
    rule: 'Nullify heap pointers immediately on free.',
    flag: '-fsanitize=address (test builds)',
  },
  {
    key: 'fmt',
    label: 'Format string',
    cwe: 'CWE-134',
    vulnCode: `void log_client_msg(char *user_input) {
    printf(user_input);
}`,
    fixedCode: `void log_client_msg(const char *user_input) {
    printf("%s", user_input);
}`,
    rule: 'Use a constant literal as the format specifier.',
    flag: '-Wformat=2 -Werror=format-security',
  },
];

export const StoryChapter4: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [activeKey, setActiveKey] = useState('overflow');

  useEffect(() => {
    const onScroll = () => {
      const p = sectionProgress(sectionRef.current);
      const idx = Math.min(2, Math.floor(p * 3.1));
      setActiveKey(DIFFS[idx].key);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, []);

  const diff = DIFFS.find((d) => d.key === activeKey)!;

  return (
    <div id="act-fix" ref={sectionRef}>
      <StoryPin>
        <div className="flex h-full flex-col overflow-auto px-4 py-10 sm:px-6 lg:px-8">
          <div className="mx-auto flex w-full max-w-7xl flex-1 flex-col gap-6">
            <div>
              <p className="kicker">Act VII · Remediation</p>
              <h2 className="display mt-3 max-w-3xl text-4xl sm:text-5xl">
                A proved violation ships with a patch sketch.
              </h2>
            </div>

            <div className="flex flex-wrap gap-px border border-line bg-line self-start">
              {DIFFS.map((d) => (
                <button
                  key={d.key}
                  type="button"
                  onClick={() => setActiveKey(d.key)}
                  className={`bg-ink px-4 py-2 font-mono text-[11px] uppercase tracking-[0.14em] ${
                    activeKey === d.key ? 'text-signal' : 'text-mute'
                  }`}
                >
                  {d.label}
                </button>
              ))}
            </div>

            <div className="flex-1 border border-line bg-ink-2 p-5">
              <div className="flex items-center justify-between border-b border-line pb-3">
                <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-mute">
                  Advisory diff
                </span>
                <span className="font-mono text-[11px] text-brass">{diff.cwe}</span>
              </div>
              <div className="mt-4 grid gap-4 md:grid-cols-2">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-hazard">Vulnerable</p>
                  <pre className="mt-2 overflow-x-auto border border-hazard/30 bg-ink p-4 font-mono text-[11px] leading-relaxed text-hazard/90">
                    {diff.vulnCode}
                  </pre>
                </div>
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-safe">Remediated</p>
                  <pre className="mt-2 overflow-x-auto border border-safe/30 bg-ink p-4 font-mono text-[11px] leading-relaxed text-safe/90">
                    {diff.fixedCode}
                  </pre>
                </div>
              </div>
              <div className="mt-4 grid gap-px border border-line bg-line sm:grid-cols-2">
                <div className="bg-ink px-4 py-3">
                  <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mute">Rule</p>
                  <p className="mt-1 text-sm text-paper">{diff.rule}</p>
                </div>
                <div className="bg-ink px-4 py-3">
                  <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-mute">Compiler flag</p>
                  <code className="mt-1 block text-xs text-brass">{diff.flag}</code>
                </div>
              </div>
            </div>
          </div>
        </div>
      </StoryPin>
    </div>
  );
};
