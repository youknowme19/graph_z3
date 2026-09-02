import React, { useEffect, useRef, useState } from 'react';
import { Wrench, FileDiff } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

const DIFFS = [
  {
    key: 'overflow',
    label: 'Buffer Overflow',
    cwe: 'CWE-121: Stack-based Buffer Overflow',
    color: 'text-cyan-400',
    border: 'border-cyan-800/40',
    accentBg: 'bg-cyan-950/20',
    vulnCode: `// ❌ Vulnerable Implementation
void handle_packet(char *user_data, size_t user_len) {
    char buffer[16];
    // Blind copy — no length guard:
    memcpy(buffer, user_data, user_len);
}`,
    fixedCode: `// ✅ Remediated Implementation
int handle_packet(char *user_data, size_t user_len) {
    char buffer[16];
    // Explicit SMT invariant enforcement:
    if (user_len > sizeof(buffer)) {
        return -EINVAL;
    }
    memcpy(buffer, user_data, user_len);
    return 0;
}`,
    rule: 'Validate buffer bounds before any memory copy operation.',
    flag: '-fstack-protector-all -D_FORTIFY_SOURCE=2',
  },
  {
    key: 'uaf',
    label: 'Use-After-Free',
    cwe: 'CWE-416: Use-After-Free',
    color: 'text-purple-400',
    border: 'border-purple-800/40',
    accentBg: 'bg-purple-950/20',
    vulnCode: `// ❌ Vulnerable Implementation
void free_session(Session *s) {
    free(s);
    // Dangling pointer dereference:
    s->status = SESSION_CLOSED;
}`,
    fixedCode: `// ✅ Remediated Implementation
void free_session(Session **s_ptr) {
    if (!s_ptr || !*s_ptr) return;
    free(*s_ptr);
    // Immediate nullification:
    *s_ptr = NULL;
}`,
    rule: 'Nullify heap pointers immediately upon deallocation.',
    flag: '-fsanitize=address (in test builds)',
  },
  {
    key: 'fmt',
    label: 'Format String',
    cwe: 'CWE-134: Uncontrolled Format String',
    color: 'text-amber-400',
    border: 'border-amber-800/40',
    accentBg: 'bg-amber-950/20',
    vulnCode: `// ❌ Vulnerable Implementation
void log_client_msg(char *user_input) {
    // User payload parsed as format string:
    printf(user_input);
}`,
    fixedCode: `// ✅ Remediated Implementation
void log_client_msg(const char *user_input) {
    // Safe constant format specifier:
    printf("%s", user_input);
}`,
    rule: 'Always use a constant literal as the format specifier.',
    flag: '-Wformat=2 -Werror=format-security',
  },
];

export const StoryChapter4: React.FC = () => {
  const sectionRef = useRef<HTMLDivElement>(null);
  const [progress, setProgress] = useState(0);
  const [activeKey, setActiveKey] = useState('overflow');

  useEffect(() => {
    const handleScroll = () => {
      if (!sectionRef.current) return;
      const rect = sectionRef.current.getBoundingClientRect();
      const h = sectionRef.current.offsetHeight - window.innerHeight;
      const p = Math.max(0, Math.min(1, -rect.top / h));
      setProgress(p);
      // Auto-cycle diffs
      const idx = Math.min(2, Math.floor(p * 3.2));
      setActiveKey(DIFFS[idx].key);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    handleScroll();
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const diff = DIFFS.find(d => d.key === activeKey)!;

  return (
    <div ref={sectionRef} className="relative" style={{ height: '280vh' }}>
      <div className="sticky top-0 h-screen flex flex-col overflow-hidden">
        {/* BG glow */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ background: 'radial-gradient(ellipse 60% 50% at 50% 70%, rgba(16,185,129,0.06) 0%, transparent 70%)' }} />

        <div className="relative z-10 flex flex-col h-full max-w-6xl mx-auto px-6 py-6 w-full gap-4">
          {/* Header */}
          <div className="text-center space-y-3">
            <div className="flex justify-center">
              <HoloSticker label="ACT V // AUTOMATED REMEDIATION" sublabel="Code Diffs & Compiler Hardening"
                variant="secure" rotation={-2} floatAnimation="gentle" icon={<Wrench className="w-4 h-4 text-emerald-300" />} />
            </div>
            <h2 className="text-4xl sm:text-5xl lg:text-6xl font-black text-slate-100 tracking-tight leading-tight">
              Instant Developer{' '}
              <span className="bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
                Fix Advisories
              </span>
            </h2>
            <p className="text-slate-400 text-sm leading-relaxed max-w-xl mx-auto">
              For every proved invariant violation, GRAPH_Z3 emits a clear code diff, CWE classification, architectural prevention rules, and compiler hardening flags.
            </p>
          </div>

          {/* Tabs */}
          <div className="flex justify-center">
            <div className="inline-flex p-1 rounded-2xl bg-slate-900 border border-slate-800 gap-1">
              {DIFFS.map(d => (
                <button key={d.key} onClick={() => setActiveKey(d.key)}
                  className={`px-4 py-2 rounded-xl text-xs font-mono font-bold tracking-wide transition-all ${
                    activeKey === d.key
                      ? `${d.accentBg} ${d.color} border ${d.border} shadow-lg`
                      : 'text-slate-500 hover:text-slate-300'
                  }`}>
                  {d.label}
                </button>
              ))}
            </div>
          </div>

          {/* Code diff */}
          <div className="flex-1 metamask-card rounded-3xl p-5 space-y-4 overflow-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2.5 font-mono text-xs font-bold text-slate-300">
                <FileDiff className="w-4 h-4 text-emerald-400" />
                AUTOMATED REMEDIATION DIFF
              </div>
              <span className={`text-[11px] font-mono font-bold ${diff.color}`}>{diff.cwe}</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-red-400 text-[11px] font-bold">VULNERABLE SOURCE</span>
                </div>
                <pre className="p-4 rounded-xl bg-[#140808] border border-red-900/40 text-red-300 overflow-x-auto leading-relaxed text-[11px]">
                  {diff.vulnCode}
                </pre>
              </div>

              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  <span className="text-emerald-400 text-[11px] font-bold">REMEDIATED IMPLEMENTATION</span>
                </div>
                <pre className="p-4 rounded-xl bg-[#081810] border border-emerald-900/40 text-emerald-300 overflow-x-auto leading-relaxed text-[11px]">
                  {diff.fixedCode}
                </pre>
              </div>
            </div>

            {/* Recommendations row */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono text-xs">
              <div className={`p-3 rounded-xl ${diff.accentBg} border ${diff.border} space-y-1`}>
                <span className="text-slate-500 text-[10px] uppercase font-bold block">Hardening Rule</span>
                <div className={`${diff.color} text-[11px] leading-relaxed`}>{diff.rule}</div>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] uppercase font-bold block">Compiler Flag</span>
                <code className="text-amber-300 text-[11px]">{diff.flag}</code>
              </div>
              <div className="p-3 rounded-xl bg-slate-900 border border-slate-800 space-y-1">
                <span className="text-slate-500 text-[10px] uppercase font-bold block">Scroll Progress</span>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden mt-2">
                  <div className="h-full bg-gradient-to-r from-emerald-500 to-teal-400 rounded-full transition-all duration-200"
                    style={{ width: `${progress * 100}%` }} />
                </div>
                <div className={`text-[10px] ${diff.color}`}>{Math.round(progress * 100)}%</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
