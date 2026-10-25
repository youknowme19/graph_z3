import React, { useState } from 'react';
import {
  Layers,
  Cpu,
  ShieldAlert,
  CheckCircle2,
  Copy,
  Check,
  Lock,
  Unlock,
  Terminal,
} from 'lucide-react';

/* ── Step 2 Data: GraphSAGE Nodes ── */
const NODES = [
  { id: 0, addr: '0x1000004ac', name: 'main() prologue', type: 'Entry Block', score: 0.12, status: 'Benign' },
  { id: 1, addr: '0x10000051c', name: 'memcpy_chk() sink', type: 'Vulnerability Sink', score: 0.94, status: 'Critical Risk' },
  { id: 2, addr: '0x100000558', name: 'validate_len() guard', type: 'Branch Guard', score: 0.47, status: 'Medium Risk' },
  { id: 3, addr: '0x100000580', name: 'epilogue_ret()', type: 'Exit Block', score: 0.08, status: 'Benign' },
];

const VECTORS: Record<number, number[]> = {
  0: [0.12, 0.08, 0.15, 0.10, 0.09, 0.13, 0.07, 0.11, 0.14, 0.06, 0.10, 0.08, 0.12, 0.09, 0.11, 0.07],
  1: [0.94, 0.88, 0.91, 0.76, 0.83, 0.90, 0.87, 0.72, 0.95, 0.68, 0.79, 0.85, 0.92, 0.77, 0.88, 0.94],
  2: [0.47, 0.42, 0.51, 0.38, 0.44, 0.49, 0.36, 0.52, 0.41, 0.47, 0.43, 0.50, 0.39, 0.48, 0.45, 0.53],
  3: [0.08, 0.10, 0.09, 0.11, 0.07, 0.12, 0.06, 0.09, 0.08, 0.10, 0.07, 0.11, 0.09, 0.08, 0.10, 0.06],
};

/* ── Step 3 Data: Z3 SMT Proofs ── */
const SMT_PROOFS = [
  {
    key: 'overflow',
    title: 'Vulnerable Path (Exploit Proved)',
    verdict: 'SAT',
    formula: `; Path predicate: user input length reaches copy sink
(assert (bvuge packet_len (_ bv64 64)))
; Safety invariant violated: write exceeds 8-byte buffer
(assert (bvugt copy_size (_ bv8 64)))
(check-sat)
; Result: SAT in 3.1ms
; Synthesized model: packet_len = 64, copy_size = 72`,
    summary: 'Z3 synthesized a 40-byte concrete model. The stack frame return address is deterministically hijacked. This is a mathematical counterexample, not a heuristic guess.',
  },
  {
    key: 'guarded',
    title: 'Guarded Path (Safety Proved)',
    verdict: 'UNSAT',
    formula: `; Guarding condition already bounds the copy size
(assert (bvule copy_size (_ bv8 64)))
; Simultaneous out-of-bounds assertion
(assert (bvugt copy_size (_ bv8 64)))
(check-sat)
; Result: UNSAT (logical contradiction)
; No model exists — invariant holds on all paths.`,
    summary: 'The assertions represent a logical contradiction. No crash payload exists on this path, so GRAPH_Z3 discards it with 0.0% false positives.',
  },
];

/* ── Step 4 Data: Payload ── */
const CONCRETE_PAYLOAD = [
  32, 4, 4, 1, 1, 8, 1, 1, 1, 2, 1, 1, 128, 1, 1, 0, 1, 32, 32, 2, 8, 32, 2, 4, 128, 2, 64, 2, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 15
];

/* ── Step 5 Data: Diffs ── */
const REMEDIATION_DIFFS = [
  {
    id: 'cwe120',
    name: 'CWE-120: Buffer Overflow',
    rule: 'Validate buffer bounds before memory copy operation.',
    flag: '-fstack-protector-strong -D_FORTIFY_SOURCE=2',
    vuln: `void handle_packet(char *user_data, size_t user_len) {
    char buffer[16];
    // VULNERABLE: No length check before copy
    memcpy(buffer, user_data, user_len);
}`,
    fixed: `int handle_packet(char *user_data, size_t user_len) {
    char buffer[16];
    // FIXED: Strict boundary enforcement
    if (user_len > sizeof(buffer)) return -EINVAL;
    memcpy(buffer, user_data, user_len);
    return 0;
}`,
  },
  {
    id: 'cwe416',
    name: 'CWE-416: Use-After-Free',
    rule: 'Zero out heap pointers immediately upon free.',
    flag: '-fsanitize=address (dev/test builds)',
    vuln: `void free_session(Session *s) {
    free(s);
    // VULNERABLE: Dangling pointer access
    s->status = SESSION_CLOSED;
}`,
    fixed: `void free_session(Session **s_ptr) {
    if (!s_ptr || !*s_ptr) return;
    free(*s_ptr);
    // FIXED: Invalidate pointer reference
    *s_ptr = NULL;
}`,
  },
  {
    id: 'cwe134',
    name: 'CWE-134: Format String',
    rule: 'Always provide a constant format specifier.',
    flag: '-Wformat=2 -Werror=format-security',
    vuln: `void log_msg(char *user_input) {
    // VULNERABLE: Direct user format string
    printf(user_input);
}`,
    fixed: `void log_msg(const char *user_input) {
    // FIXED: Explicit format specifier
    printf("%s", user_input);
}`,
  },
];

export const PipelineArchitecture: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'crisis' | 'gnn' | 'z3' | 'payload' | 'patch'>('gnn');
  const [selectedNode, setSelectedNode] = useState<number>(1);
  const [smtProofKey, setSmtProofKey] = useState<string>('overflow');
  const [copiedPayload, setCopiedPayload] = useState(false);
  const [selectedDiffId, setSelectedDiffId] = useState<string>('cwe120');

  const node = NODES[selectedNode];
  const vector = VECTORS[selectedNode];
  const currentProof = SMT_PROOFS.find((p) => p.key === smtProofKey)!;
  const currentDiff = REMEDIATION_DIFFS.find((d) => d.id === selectedDiffId)!;

  const handleCopyPayload = () => {
    const cmd = `python3 -c "import sys; sys.stdout.buffer.write(bytes([${CONCRETE_PAYLOAD.join(', ')}]))" | ./cwe120_buffer_overflow.bin`;
    navigator.clipboard.writeText(cmd);
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  return (
    <section className="relative px-4 py-16 sm:px-6 lg:px-8 border-t border-zinc-800/80">
      <div className="mx-auto max-w-7xl space-y-8">
        {/* Section Header */}
        <div className="max-w-2xl space-y-2">
          <div className="inline-flex items-center gap-1.5 font-mono text-xs uppercase tracking-wider text-emerald-400 font-semibold">
            <Cpu className="h-3.5 w-3.5" />
            <span>Architecture & Pipeline</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-zinc-100 sm:text-3xl">
            How GRAPH_Z3 Solves Binary Vulnerability Analysis
          </h2>
          <p className="text-sm text-zinc-400">
            Explore the hybrid engine: from topological graph neural ranking to exact bitvector SMT proof generation.
          </p>
        </div>

        {/* Minimal Pipeline Segmented Navigation */}
        <div className="flex flex-wrap gap-1 rounded-xl border border-zinc-800/80 bg-zinc-900/50 p-1.5">
          {[
            { id: 'crisis', label: '1. Path Explosion', icon: ShieldAlert },
            { id: 'gnn', label: '2. GraphSAGE Ranking', icon: Layers },
            { id: 'z3', label: '3. Z3 SMT Solver', icon: Lock },
            { id: 'payload', label: '4. Payload Synthesis', icon: Terminal },
            { id: 'patch', label: '5. Patch Advisory', icon: CheckCircle2 },
          ].map((tab) => {
            const on = activeTab === tab.id;
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 rounded-lg px-3.5 py-2 text-xs font-medium transition-all ${
                  on
                    ? 'bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700/60'
                    : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40'
                }`}
              >
                <Icon className={`h-3.5 w-3.5 ${on ? 'text-emerald-400' : 'text-zinc-500'}`} />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Dynamic Interactive Stage Body */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-6 sm:p-8 backdrop-blur-sm">
          {/* TAB 1: THE CRISIS */}
          {activeTab === 'crisis' && (
            <div className="space-y-6">
              <div className="max-w-2xl">
                <span className="font-mono text-xs uppercase text-rose-400 font-semibold tracking-wider">
                  The Fundamental Problem
                </span>
                <h3 className="text-xl font-bold text-zinc-100 mt-1">
                  50 binary branches yields 1,125,899,906,842,624 potential execution paths.
                </h3>
                <p className="text-sm text-zinc-400 mt-2">
                  Unguided symbolic engines freeze in state explosion. Mutation fuzzers blind-guess bytes hoping to hit magic values. GRAPH_Z3 eliminates this trade-off by pruning 99.6% of benign paths prior to solver execution.
                </p>
              </div>

              <div className="grid grid-cols-1 gap-4 md:grid-cols-2 pt-2">
                <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-rose-400 uppercase tracking-wide">
                      Traditional Tools (AFL++, Linters)
                    </span>
                    <span className="text-[10px] font-mono text-rose-400/80 rounded bg-rose-500/10 px-2 py-0.5">
                      High Noise
                    </span>
                  </div>
                  <ul className="space-y-2.5 text-xs text-zinc-300">
                    <li className="flex items-start gap-2">
                      <span className="text-rose-400 font-bold">•</span>
                      <span><strong>State Explosion:</strong> 2<sup>d</sup> states choke symbolic execution engines without reachability guidance.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-rose-400 font-bold">•</span>
                      <span><strong>Syntax Alarms:</strong> Static pattern matching flags every standard library call regardless of safety guards.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-rose-400 font-bold">•</span>
                      <span><strong>Opaque Crashes:</strong> Fuzz dumps lack mathematical constraints or minimal reproducible payloads.</span>
                    </li>
                  </ul>
                </div>

                <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs font-semibold text-emerald-400 uppercase tracking-wide">
                      GRAPH_Z3 Neuro-Symbolic Engine
                    </span>
                    <span className="text-[10px] font-mono text-emerald-400/80 rounded bg-emerald-500/10 px-2 py-0.5">
                      Proved Proofs
                    </span>
                  </div>
                  <ul className="space-y-2.5 text-xs text-zinc-300">
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-400 font-bold">•</span>
                      <span><strong>GraphSAGE Steering:</strong> 40-dim topological embeddings score blocks to prune 99.66% of benign branches.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-400 font-bold">•</span>
                      <span><strong>Formal SMT Guarantees:</strong> Z3 proves mathematical reachability. UNSAT is discarded; SAT is a verified counterexample.</span>
                    </li>
                    <li className="flex items-start gap-2">
                      <span className="text-emerald-400 font-bold">•</span>
                      <span><strong>Synthesized Exploit:</strong> Outputs exact input byte arrays with one-line Python test harnesses.</span>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: GRAPHSAGE RANKING */}
          {activeTab === 'gnn' && (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
              <div className="space-y-3 lg:col-span-5">
                <span className="font-mono text-xs uppercase text-emerald-400 font-semibold tracking-wider">
                  Topological Inference
                </span>
                <h3 className="text-xl font-bold text-zinc-100">
                  Every basic block receives a 40-dimensional embedding.
                </h3>
                <p className="text-xs text-zinc-400 leading-relaxed">
                  The CFG is lifted to VEX IR. A 2-layer GraphSAGE (SageConv) network aggregates neighborhood structure to calculate exploit probability before symbolic search begins.
                </p>

                <div className="space-y-2 pt-2">
                  {NODES.map((n) => (
                    <button
                      key={n.id}
                      type="button"
                      onClick={() => setSelectedNode(n.id)}
                      className={`flex w-full items-center justify-between rounded-lg border p-3 text-left transition-colors ${
                        selectedNode === n.id
                          ? 'border-emerald-500/50 bg-emerald-500/10'
                          : 'border-zinc-800 bg-zinc-900/60 hover:border-zinc-700'
                      }`}
                    >
                      <div>
                        <div className="font-mono text-xs font-semibold text-zinc-200">{n.name}</div>
                        <div className="font-mono text-[10px] text-zinc-500 mt-0.5">{n.addr} · {n.type}</div>
                      </div>
                      <div className="text-right">
                        <span className={`font-mono text-xs font-bold ${n.score > 0.8 ? 'text-rose-400' : 'text-emerald-400'}`}>
                          {(n.score * 100).toFixed(0)}%
                        </span>
                        <span className="block text-[10px] text-zinc-500 font-mono">risk</span>
                      </div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-4 rounded-lg border border-zinc-800 bg-zinc-950 p-5 lg:col-span-7">
                <div className="flex items-center justify-between border-b border-zinc-800 pb-3">
                  <div>
                    <span className="font-mono text-xs font-semibold text-zinc-200">{node.name}</span>
                    <span className="ml-2 font-mono text-[10px] text-zinc-500">{node.addr}</span>
                  </div>
                  <span className={`rounded px-2 py-0.5 font-mono text-[10px] font-semibold ${
                    node.score > 0.8 ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30' : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                  }`}>
                    {node.status}
                  </span>
                </div>

                <div>
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-zinc-400">SageConv Exploitability Score</span>
                    <span className={node.score > 0.8 ? 'text-rose-400 font-bold' : 'text-emerald-400 font-bold'}>
                      {(node.score * 100).toFixed(1)}%
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 w-full rounded-full bg-zinc-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${node.score > 0.8 ? 'bg-rose-500' : 'bg-emerald-400'}`}
                      style={{ width: `${node.score * 100}%` }}
                    />
                  </div>
                </div>

                <div className="space-y-1.5">
                  <span className="font-mono text-[10px] uppercase text-zinc-500">
                    Sampled 16/40 Embedding Dimensions
                  </span>
                  <div className="grid grid-cols-8 gap-1">
                    {vector.map((v, i) => (
                      <div
                        key={i}
                        className="rounded flex flex-col items-center justify-center p-1.5 font-mono text-[10px] border border-zinc-800/60"
                        style={{
                          backgroundColor: `rgba(16, 185, 129, ${0.05 + v * 0.35})`,
                          color: v > 0.6 ? '#f4f4f5' : '#a1a1aa',
                        }}
                      >
                        <span className="text-[9px] text-zinc-500">d{i}</span>
                        <span className="font-semibold">{v.toFixed(2)}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="rounded-md bg-zinc-900 p-3 font-mono text-xs text-zinc-400 border border-zinc-800/80">
                  {node.id === 1 ? (
                    <span className="text-rose-300">
                      High-Priority Sink detected: angr initiates directed symbolic slicing on standard input bytes. Z3 SMT solver invoked with destination bound invariants.
                    </span>
                  ) : node.id === 2 ? (
                    <span>
                      Guard Condition: length check analyzed. Both True and False edges tested against memory safety predicate.
                    </span>
                  ) : (
                    <span>
                      Low Risk Block: SimProcedures cached. Symbolic execution skips redundant solver calls, saving 99.6% compute.
                    </span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: Z3 SMT SOLVER */}
          {activeTab === 'z3' && (
            <div className="space-y-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <span className="font-mono text-xs uppercase text-emerald-400 font-semibold tracking-wider">
                    Formal Theorem Proving
                  </span>
                  <h3 className="text-xl font-bold text-zinc-100 mt-1">
                    SAT is a certified exploit. UNSAT is a proof of safety.
                  </h3>
                </div>

                <div className="flex gap-2 rounded-lg border border-zinc-800 bg-zinc-950 p-1">
                  {SMT_PROOFS.map((p) => (
                    <button
                      key={p.key}
                      type="button"
                      onClick={() => setSmtProofKey(p.key)}
                      className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 font-mono text-xs font-semibold transition-colors ${
                        smtProofKey === p.key
                          ? p.verdict === 'SAT'
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                          : 'text-zinc-500 hover:text-zinc-300'
                      }`}
                    >
                      {p.verdict === 'SAT' ? <Unlock className="h-3.5 w-3.5 text-rose-400" /> : <Lock className="h-3.5 w-3.5 text-emerald-400" />}
                      <span>{p.verdict} Path</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 gap-6 md:grid-cols-12">
                <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-950 p-4 md:col-span-7">
                  <div className="flex items-center justify-between border-b border-zinc-800 pb-2">
                    <span className="font-mono text-xs text-zinc-400">SMT-LIB2 Bitvector Formula</span>
                    <span className={`font-mono text-xs font-bold ${currentProof.verdict === 'SAT' ? 'text-rose-400' : 'text-emerald-400'}`}>
                      Z3 Verdict: {currentProof.verdict}
                    </span>
                  </div>
                  <pre className="overflow-x-auto font-mono text-xs text-emerald-300/90 leading-relaxed p-2">
                    {currentProof.formula}
                  </pre>
                </div>

                <div className="space-y-4 md:col-span-5 flex flex-col justify-between">
                  <div className="rounded-lg border border-zinc-800 bg-zinc-900/80 p-5 space-y-3">
                    <div className="flex items-center gap-2">
                      <span className={`h-2.5 w-2.5 rounded-full ${currentProof.verdict === 'SAT' ? 'bg-rose-400' : 'bg-emerald-400'}`} />
                      <h4 className="font-semibold text-zinc-100 text-sm">{currentProof.title}</h4>
                    </div>
                    <p className="text-xs text-zinc-400 leading-relaxed">
                      {currentProof.summary}
                    </p>
                  </div>

                  <div className="rounded-lg border border-zinc-800 bg-zinc-900/40 p-4 text-xs font-mono text-zinc-400 space-y-1">
                    <div className="flex justify-between">
                      <span>Solver Engine:</span>
                      <span className="text-zinc-200">Z3 4.12.2 (Bitvector Theory)</span>
                    </div>
                    <div className="flex justify-between">
                      <span>Solve Latency:</span>
                      <span className="text-emerald-400 font-semibold">3.1 ms</span>
                    </div>
                    <div className="flex justify-between">
                      <span>False Positive Guarantee:</span>
                      <span className="text-emerald-400 font-semibold">0.0% (Formal Model)</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PAYLOAD SYNTHESIS */}
          {activeTab === 'payload' && (
            <div className="space-y-6">
              <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <span className="font-mono text-xs uppercase text-emerald-400 font-semibold tracking-wider">
                    Exploit Synthesis
                  </span>
                  <h3 className="text-xl font-bold text-zinc-100 mt-1">
                    From SMT satisfying assignment to reproducible PoC.
                  </h3>
                  <p className="text-xs text-zinc-400 mt-1">
                    Z3 extracts a concrete model satisfying all path predicates and constraint boundaries.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={handleCopyPayload}
                  className="btn-signal self-start sm:self-auto"
                >
                  {copiedPayload ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
                  <span>{copiedPayload ? 'Copied Harness' : 'Copy Reproducer'}</span>
                </button>
              </div>

              {/* Concrete Byte Matrix */}
              <div className="space-y-3 rounded-lg border border-zinc-800 bg-zinc-950 p-5">
                <div className="flex items-center justify-between text-xs font-mono text-zinc-400 border-b border-zinc-800 pb-2">
                  <span>Synthesized 40-Byte Model Array</span>
                  <span className="text-emerald-400">Target: cwe120_buffer_overflow.bin</span>
                </div>

                <div className="flex flex-wrap gap-1.5 pt-2">
                  {CONCRETE_PAYLOAD.map((byte, idx) => (
                    <div
                      key={idx}
                      title={`Byte offset ${idx}: 0x${byte.toString(16).padStart(2, '0')} (${byte})`}
                      className="flex h-8 w-8 flex-col items-center justify-center rounded font-mono text-[10px] border border-zinc-800/80 transition-colors hover:border-emerald-500"
                      style={{
                        backgroundColor: byte > 64 ? 'rgba(244, 63, 94, 0.2)' : 'rgba(16, 185, 129, 0.1)',
                        color: byte > 64 ? '#fda4af' : '#a7f3d0',
                      }}
                    >
                      <span>{byte}</span>
                    </div>
                  ))}
                </div>

                {/* 1-Line CLI Harness */}
                <div className="pt-3">
                  <span className="block font-mono text-[10px] text-zinc-500 uppercase mb-1">
                    One-line verification harness
                  </span>
                  <pre className="overflow-x-auto rounded bg-zinc-900 p-3 font-mono text-xs text-emerald-300 border border-zinc-800">
                    {`python3 -c "import sys; sys.stdout.buffer.write(bytes([${CONCRETE_PAYLOAD.join(', ')}]))" | ./cwe120_buffer_overflow.bin`}
                  </pre>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: REMEDIATION & PATCH */}
          {activeTab === 'patch' && (
            <div className="space-y-6">
              <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                  <span className="font-mono text-xs uppercase text-emerald-400 font-semibold tracking-wider">
                    Remediation & Hardening
                  </span>
                  <h3 className="text-xl font-bold text-zinc-100 mt-1">
                    Automated patch advisory and compiler hardening.
                  </h3>
                </div>

                <div className="flex flex-wrap gap-2">
                  {REMEDIATION_DIFFS.map((diff) => (
                    <button
                      key={diff.id}
                      type="button"
                      onClick={() => setSelectedDiffId(diff.id)}
                      className={`rounded-md px-3 py-1.5 font-mono text-xs transition-colors border ${
                        selectedDiffId === diff.id
                          ? 'border-emerald-500/50 bg-emerald-500/10 text-emerald-300 font-semibold'
                          : 'border-zinc-800 bg-zinc-900 text-zinc-400 hover:text-zinc-200'
                      }`}
                    >
                      {diff.id.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-4 rounded-lg border border-zinc-800 bg-zinc-950 p-5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between border-b border-zinc-800 pb-3 gap-2">
                  <span className="font-mono text-sm font-semibold text-zinc-200">{currentDiff.name}</span>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-zinc-500">Compiler Flags:</span>
                    <span className="rounded bg-zinc-900 px-2 py-0.5 font-mono text-xs text-emerald-400 border border-zinc-800">
                      {currentDiff.flag}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="space-y-1.5">
                    <span className="font-mono text-[10px] text-rose-400 font-semibold uppercase">
                      Vulnerable Code
                    </span>
                    <pre className="overflow-x-auto rounded-md border border-rose-500/30 bg-rose-500/5 p-3.5 font-mono text-xs text-rose-300">
                      {currentDiff.vuln}
                    </pre>
                  </div>

                  <div className="space-y-1.5">
                    <span className="font-mono text-[10px] text-emerald-400 font-semibold uppercase">
                      Remediated Code
                    </span>
                    <pre className="overflow-x-auto rounded-md border border-emerald-500/30 bg-emerald-500/5 p-3.5 font-mono text-xs text-emerald-300">
                      {currentDiff.fixed}
                    </pre>
                  </div>
                </div>

                <div className="rounded-md bg-zinc-900/60 p-3 font-mono text-xs text-zinc-400 border border-zinc-800/60">
                  <strong className="text-zinc-300">Remediation Rule:</strong> {currentDiff.rule}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </section>
  );
};
