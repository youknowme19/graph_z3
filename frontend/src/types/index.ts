export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface LogEntry {
  ts: number;
  level: 'INIT' | 'CONFIG' | 'INFO' | 'GRAPH' | 'SECURITY' | 'GNN' | 'SMT' | 'STEP' | 'VULN' | 'SCAN' | 'SUCCESS' | 'WARN' | 'ERROR' | string;
  msg: string;
}

export interface Mitigations {
  PIE: boolean;
  NX: boolean;
  STACK_CANARY: boolean;
  FULL_RELRO: boolean;
  PARTIAL_RELRO: boolean;
  FORTIFY: boolean;
}

export interface BinaryInfo {
  filename: string;
  size_bytes?: number;
  arch?: string;
  entry?: string;
  sha256?: string;
}

export interface ExploitPrimitive {
  primitive_type: string;
  title: string;
  description: string;
  reliability: 'HIGH' | 'MEDIUM' | 'LOW';
  mitigations_present: string[];
  mitigations_bypassed: string[];
  mitigations_blocking: string[];
  cvss_base_score: number;
  cve_similar: string[];
  attacker_capability: string;
}

export interface Counterfactual {
  mitigation: string;
  scenario: string;
  impact: string;
  new_score: number;
}

export interface EreVerdict {
  verdict: 'YES' | 'NO' | 'CONDITIONAL';
  hackability_score: number;
  formal_reasons?: string[];
  counterfactuals?: Counterfactual[];
}

export interface FixAdvice {
  summary: string;
  cwe?: string;
  unsafe_pattern?: string;
  safe_alternative?: string;
  steps?: string[];
  before?: string;
  after?: string;
  prevention?: string;
  source?: 'llm' | 'rule-based' | 'error' | string;
  unsafe_call?: string;
}

export interface ExploitVar {
  name: string;
  size: number;
  hex: string;
  ascii: string;
}

export interface Vulnerability {
  vuln_type: string;
  vuln_severity: SeverityLevel;
  address: string;
  function_name: string;
  vuln_details: string;
  exploit_primitive?: ExploitPrimitive;
  cwe?: string;
  reproduce_cmd?: string;
  ere_verdict?: EreVerdict;
  solver_proof?: string;
  fix_advice?: FixAdvice;
  exploit_vars?: ExploitVar[];
  crash_integers?: number[];
  crash_length?: number;
}

export interface SMTDiagnostics {
  status: 'SAT' | 'UNSAT' | 'UNKNOWN' | 'N/A';
  constraint_annotations?: string[];
  symbolic_variables_list?: Array<{ name: string; size_bits?: number; type?: string }>;
  solver_time_ms?: number;
  model?: string;
  statistics?: string;
}

export interface ExecutionState {
  function_name: string;
  basic_block: string;
  instruction_address: string;
  execution_depth: number;
  symbolic_variables: string;
  path_constraints: string;
  solver_status: string;
  model_information: string;
  explanation: string;
  next_state: string;
  is_library?: boolean;
  is_branch?: boolean;
  event_type?: 'ENTRY' | 'RETURN' | 'BRANCH' | 'LOOP' | 'LIBRARY_CALL' | 'SYSCALL' | 'NORMAL';
  is_vulnerable?: boolean;
  vuln_type?: string;
  vuln_severity?: string;
  vuln_details?: string;
  smt_diagnostics?: SMTDiagnostics;
}

export interface GraphNode {
  data: {
    id: string;
    label: string;
    node_class?: string;
    is_loop_header?: boolean;
    gnn_predicted_vulnerable?: boolean;
    instruction_count?: number;
    cyclomatic_complexity?: number;
    entropy?: number;
    disasm?: string[];
    [key: string]: any;
  };
  classes?: string;
}

export interface GraphEdge {
  data: {
    id: string;
    source: string;
    target: string;
    edge_type?: string;
  };
  classes?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AnalysisMetrics {
  total_functions?: number;
  total_blocks?: number;
  total_edges?: number;
  trace_states?: number;
  sat_states?: number;
  unsat_states?: number;
  total_vulnerabilities?: number;
  critical_count?: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
  max_cvss?: number;
  elapsed_seconds?: number;
}

export interface AnalysisJob {
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: number;
  logs: LogEntry[];
  metrics: AnalysisMetrics;
  cfg: GraphData;
  cg: GraphData;
  trace: ExecutionState[];
  vulnerabilities: Vulnerability[];
  mitigations: Mitigations;
  binary_info: BinaryInfo;
  error?: string;
}

export interface SampleBinary {
  id: string;
  name: string;
  category: string;
  cwe?: string;
  arch: string;
  severity: SeverityLevel;
  description: string;
  has_binary: boolean;
}
