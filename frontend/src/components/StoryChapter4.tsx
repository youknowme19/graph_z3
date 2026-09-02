import React, { useState } from 'react';
import { Code2, CheckCircle2, Shield, Wrench, FileDiff } from 'lucide-react';
import { HoloSticker } from './HoloSticker';

export const StoryChapter4: React.FC = () => {
  const [activeVulnerability, setActiveVulnerability] = useState<'overflow' | 'uaf' | 'fmt'>('overflow');

  const diffExamples = {
    overflow: {
      cwe: 'CWE-121: Stack-based Buffer Overflow',
      vulnCode: `// ❌ Vulnerable Implementation\nvoid handle_packet(char *user_data, size_t user_len) {\n    char buffer[16];\n    // Blind copy overflows stack frame:\n    memcpy(buffer, user_data, user_len);\n}`,
      fixedCode: `// ✅ Remediated Secure Implementation\nint handle_packet(char *user_data, size_t user_len) {\n    char buffer[16];\n    // Strict SMT invariant enforcement:\n    if (user_len > sizeof(buffer)) {\n        return -EINVAL;\n    }\n    memcpy(buffer, user_data, user_len);\n    return 0;\n}`,
      fixRule: 'Validate buffer bounds explicitly before any memory copy operation.',
      prevention: 'Compile with -fstack-protector-all -D_FORTIFY_SOURCE=2.',
    },
    uaf: {
      cwe: 'CWE-416: Use-After-Free',
      vulnCode: `// ❌ Vulnerable Implementation\nvoid free_session(Session *s) {\n    free(s);\n    // Dangling pointer dereference:\n    s->status = SESSION_CLOSED;\n}`,
      fixedCode: `// ✅ Remediated Secure Implementation\nvoid free_session(Session **s_ptr) {\n    if (!s_ptr || !*s_ptr) return;\n    free(*s_ptr);\n    // Immediate pointer nullification:\n    *s_ptr = NULL;\n}`,
      fixRule: 'Nullify heap pointers immediately upon deallocation.',
      prevention: 'Enable AddressSanitizer (-fsanitize=address) in regression tests.',
    },
    fmt: {
      cwe: 'CWE-134: Uncontrolled Format String',
      vulnCode: `// ❌ Vulnerable Implementation\nvoid log_client_msg(char *user_input) {\n    // User payload directly parsed as format string:\n    printf(user_input);\n}`,
      fixedCode: `// ✅ Remediated Secure Implementation\nvoid log_client_msg(char *user_input) {\n    // Safe constant specifier:\n    printf("%s", user_input);\n}`,
      fixRule: 'Always specify a constant format specifier string.',
      prevention: 'Enable compiler flag -Wformat=2 -Werror=format-security.',
    },
  };

  const current = diffExamples[activeVulnerability];

  return (
    <section className="relative py-16 space-y-12">
      <div className="flex justify-center">
        <HoloSticker
          label="ACT V // AUTOMATED REMEDIATION"
          sublabel="Code Diffs & Hardened Compiler Flags"
          variant="secure"
          rotation={-2}
          floatAnimation="gentle"
          icon={<Wrench className="w-4 h-4 text-emerald-300" />}
        />
      </div>

      <div className="text-center space-y-4 max-w-3xl mx-auto px-4">
        <h2 className="text-3xl sm:text-4xl lg:text-5xl font-black text-slate-100 tracking-tight">
          Instant Developer{' '}
          <span className="bg-gradient-to-r from-emerald-400 via-teal-300 to-cyan-400 bg-clip-text text-transparent">
            Fix Advisories
          </span>
        </h2>
        <p className="text-slate-400 text-sm sm:text-base leading-relaxed">
          GRAPH_Z3 bridges the gap between binary exploitation and source remediation. For every proved invariant violation, it produces a clear code diff, architectural prevention rules, and compiler hardening flags.
        </p>
      </div>

      {/* Interactive Code Remediation Showcase */}
      <div className="max-w-4xl mx-auto px-4">
        <div className="metamask-card rounded-3xl p-6 sm:p-8 space-y-6">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div className="flex items-center gap-2.5 font-mono text-sm font-bold text-slate-200">
              <FileDiff className="w-4 h-4 text-emerald-400" />
              <span>AUTOMATED CODE REMEDIATION DIFF</span>
            </div>
            <div className="flex gap-2">
              <button
                onClick={() => setActiveVulnerability('overflow')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
                  activeVulnerability === 'overflow'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Buffer Overflow
              </button>
              <button
                onClick={() => setActiveVulnerability('uaf')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
                  activeVulnerability === 'uaf'
                    ? 'bg-purple-500/20 text-purple-300 border border-purple-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Use-After-Free
              </button>
              <button
                onClick={() => setActiveVulnerability('fmt')}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-bold transition-all ${
                  activeVulnerability === 'fmt'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                    : 'bg-slate-800 text-slate-400'
                }`}
              >
                Format String
              </button>
            </div>
          </div>

          <div className="font-mono text-xs text-slate-300 font-bold">
            Target Vulnerability: <span className="text-cyan-400">{current.cwe}</span>
          </div>

          {/* Before & After Diff Blocks */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
            <div className="space-y-2">
              <span className="text-red-400 text-[11px] font-bold block">
                [BEFORE] VULNERABLE SOURCE
              </span>
              <pre className="p-4 rounded-xl bg-[#140808] border border-red-900/40 text-red-300 overflow-x-auto leading-relaxed">
                <code>{current.vulnCode}</code>
              </pre>
            </div>

            <div className="space-y-2">
              <span className="text-emerald-400 text-[11px] font-bold block">
                [AFTER] REMEDIATED IMPLEMENTATION
              </span>
              <pre className="p-4 rounded-xl bg-[#081810] border border-emerald-900/40 text-emerald-300 overflow-x-auto leading-relaxed">
                <code>{current.fixedCode}</code>
              </pre>
            </div>
          </div>

          {/* Actionable Recommendations */}
          <div className="p-4 rounded-2xl bg-slate-950 border border-slate-800 grid grid-cols-1 sm:grid-cols-2 gap-4 font-mono text-xs">
            <div className="space-y-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">
                Hardening Rule:
              </span>
              <div className="text-slate-300 text-[11px]">{current.fixRule}</div>
            </div>
            <div className="space-y-1">
              <span className="text-slate-500 text-[10px] uppercase font-bold block">
                CI/CD Prevention:
              </span>
              <div className="text-emerald-300 text-[11px]">{current.prevention}</div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};
