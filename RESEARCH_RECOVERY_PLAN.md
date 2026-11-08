# NEUROZ3 — RESEARCH RECOVERY AND PUBLICATION READINESS PLAN

**Repository:** `/Volumes/WD_Subharup/Major Project/graph_z3`  
**Audit & Investigation Date:** 2026-11-08  
**Hardware Environment Verified:** Apple M4 (10-core CPU, 16 GB RAM, MPS GPU acceleration enabled), Python 3.10, PyTorch 2.9.1, `angr` 9.2.149, `claripy` 9.2.149, `xgboost` 3.2.0.

---

## 1. VERIFIED ISSUE LIST (WITH EXACT SOURCE EVIDENCE & REPRODUCTION)

Every allegation from the 9-phase rejection audit was independently tested against the repository source code, compiled binaries, PyG `.pt` graph datasets, and JSON result files. Below are the **verified issues** confirmed with exact file paths, line numbers, and live reproduction output.

### 1.1 Scientific Reporting & Manuscript-to-Artifact Discrepancies

| ID | Issue Summary | Manuscript Location (`research_paper/paper.tex`) | Ground-Truth Artifact / Code Location | Verified Discrepancy |
| :--- | :--- | :--- | :--- | :--- |
| **REP-01** | **Suppressed Zero-Shot F1 Score** | Table V (`paper.tex:501`) prints `---` for `Zero-Shot Unseen OSS Repos` F1. | `benchmark_gnn_results.json:1637-1639` (`zero_shot_generalization.metrics`) | Actual JSON records `"precision": 0.1818`, `"recall": 0.0079`, `"f1": 0.0151`. |
| **REP-02** | **Suppressed Zero F1 Scores & Mismatched CWE-327 F1 in Table VIII** | Table VIII (`paper.tex:694-702`) prints `---` for `CWE-189`, `CWE-284`, `CWE-125`, `CWE-787`, `CWE-20`, and prints `0.2500` for `CWE-327`. | `benchmark_gnn_results.json:897-1341` (`per_cwe`) | Actual JSON records `"precision": 0.0, "recall": 0.0, "f1": 0.0` for `CWE-189`, `CWE-284`, `CWE-125`, `CWE-787`, `CWE-20`, AND `"f1": 0.0` for `CWE-327` (`tp: 0, fp: 2, fn: 4`). |
| **REP-03** | **Unreported Clean-Binary False Positive Rate (FPR) on PrimeVul** | Table III (`paper.tex:397-413`) omits `clean_binary_fpr` across evaluation cohorts. | `benchmark_gnn_results.json:627, 681` | On `primevul_heldout_subset_test` (220 vulnerable + 220 clean post-patch binaries), `"clean_binary_fpr": 0.99545` (219/220 clean binaries trigger $\ge 1$ false-positive node alert at $\tau^*=0.538$) and `"f1": 0.1753`. On `primevul_standalone_real_cve_test`, `"clean_binary_fpr": 0.6419`. |
| **REP-04** | **Symbolic Benchmark Solver Crash Masked as "Exploration Depth Bounds"** | Section IV-D (`paper.tex:523-526`) & Table VI (`paper.tex:547-557`) claim 66/71 SAT proofs and state the remaining 5 candidates "reached exploration depth bounds". | `benchmark_symbolic_results.json:52, 135, 256, 270` | 4 of the 5 non-SAT candidates (`cwe120_buffer_overflow.bin` finding 1, `cwe416_use_after_free.bin` findings 1 & 2, `test_benchmarks_binary` finding 1) actually crashed with `"solver_status": "ERROR: 'method' object is not iterable"`. Only 1 finding (`test_benchmarks_binary` finding 2) was `"UNSAT"`. |
| **REP-05** | **Symbolic Benchmark Evaluated on 30 Unstripped Juliet Training Binaries of a Single Testcase** | Table VI (`paper.tex:549`) claims `Juliet Known-Vuln Suite (30 bins)` validates `STACK_OVERFLOW / NULL_DEREF` across the Juliet suite. | `benchmark_symbolic_results.json:322-800` | All 30 binaries are `data/train_binaries/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01..30.out` (from the training directory), and all 60 findings are `NULL_DEREF` in `main` (`0x401849` / `0x401857`), detecting 0 stack overflows on those 30 binaries. |
| **REP-06** | **Federated Learning Claim Contradicts Logged Metrics** | Section IV-E (`paper.tex:585-626`) & Table VII claim `FedProx ($\mu=0.002$)` mitigates weight divergence and outperforms `FedAvg`. | `benchmark_gnn_results.json:1772-1933` (`federated_learning`) | `FedAvg ($\mu=0.0$)` outperforms `FedProx ($\mu=0.002$)` on F1 (`0.2977` vs. `0.2687`), PR-AUC (`0.2385` vs. `0.2175`), Top-1 (`48.95%` vs. `47.39%`), Top-5 (`80.66%` vs. `78.40%`), and Clean-Binary FPR (`49.80%` vs. `73.88%`). `FedProx` only has higher Recall (`45.81%` vs. `37.90%`) and Top-10 (`88.15%` vs. `87.11%`). |

---

### 1.2 Symbolic Execution Engine & Exploit Synthesis Bugs

| ID | Issue Summary | Source File & Lines | Reproduction & Root Cause |
| :--- | :--- | :--- | :--- |
| **SYM-01** | **Claripy `c.leaf_asts` Method Iteration Bug** | `src/core/interfaces.py:479-484` (`is_variable_used_in_constraints`) | `for leaf in c.leaf_asts:` iterates over the bound method `c.leaf_asts` instead of calling `c.leaf_asts()`. Reproduced live: `TypeError("'method' object is not iterable")`. Because `is_variable_used_in_constraints` is called inside the `try` block of `scan_vulnerabilities()` (`interfaces.py:1273`) *after* `Z3Interface.evaluate_path()` succeeds, this exception overwrites `solver_status = "SAT"` with `"ERROR: 'method' object is not iterable"` (`interfaces.py:1342`). |
| **SYM-02** | **Fabricated Fallback Payload `[65] * 40` (`'A' * 40`)** | `src/core/interfaces.py:1312-1359` (`scan_vulnerabilities`) | Whenever `all_bytes` is empty (lines 1312–1318), `solver_status != "SAT"` (lines 1332–1339), or an exception occurs (lines 1343–1349), `scan_vulnerabilities()` fabricates `synth_bytes = [65] * 40` (`"41" * 40` hex) and populates `exploit_vars` with a synthetic variable (`status = "FALLBACK (UNSAT)"` or `"FALLBACK (ERROR)"`). This directly violates Rule 4 ("Never generate fake exploit payloads"). |
| **SYM-03** | **Mach-O Stub Hook Collision Breaking Format-String & Command-Injection Detection** | `src/core/binary_loader.py:162-185` vs. `src/core/property_engine.py:143-189` | On 2026-11-06, `BinaryLoader._get_simprocedure_for_name()` hooked `printf`/`fprintf` with `ReturnUnconstrained` (without preserving `display_name="printf"`) and hooked `snprintf`/`snprintf_chk` with `SafeSnprintf` (which overwrites `dst_ptr` with concrete `b'A'*64`, destroying taint from format arguments). Reproduced live: `cwe134_format_string.bin` and `cwe78_command_injection.bin` currently return `[]` in `scan_vulnerabilities()`. |
| **SYM-04** | **Algorithm 1 / Eq. (5) Risk-Prioritized Scheduler $\mathcal{H}(s)$ Not Implemented** | `src/core/interfaces.py:639-999, 1492-1522` | `paper.tex` Eq. (5) and Algorithm 1 specify a `MaxHeap` scheduler ordered by $\mathcal{H}(s) = \max_{v \in \text{Reachable}(s)} P_{\text{GNN}}(v) - \lambda \cdot \text{Depth}(s)$. In reality, `_run_trace()` uses a LIFO DFS stack (`stack.pop()`, line 639), only binary-sorts immediate branch successors by a boolean function flag `gnn_vulnerable_functions.get(fn.addr, False)` (lines 973–980), and falls back to under-constrained per-function isolated sweeps (`inject_symbolic_function_args`, lines 1496–1517). |
| **SYM-05** | **No Live Native Crash Replay Verification** | `src/core/interfaces.py:1215-1522` | `paper.tex` Algorithm 1 line 23 (`ReplayCrashLive(B, e)`) and Section III-E claim every synthesized witness is replayed natively against the target binary to confirm `SIGSEGV`/`SIGABRT`. No subprocess execution or signal verification of synthesized witnesses exists in `scan_vulnerabilities()`. |
| **SYM-06** | **`tests/test_all.py` Default Binary Path Points Outside Repository** | `tests/test_all.py:19-22` | `_test_vuln_path` resolves to `/Volumes/WD_Subharup/Major Project/test_vuln` (an external binary outside `graph_z3`), causing `test_scan_vulnerabilities` in `tests/test_all.py` to fail (`AssertionError: Expected STACK_OVERFLOW, SYMBOLIC_PC, or CRASH, got []`), whereas `tests/test_benchmarks_binary` inside the repo passes. |

---

### 1.3 GNN Architecture, Feature Extractor & Mathematical Formulation Mismatches

| ID | Issue Summary | Source File & Lines | Verified Evidence |
| :--- | :--- | :--- | :--- |
| **GNN-01** | **Three Redundant/Duplicate Features in the 40-D Feature Vector** | `src/graph/feature_extractor.py:193-204, 594-618` | 1. Feature 0 (`in_degree`) and Feature 5 (`num_predecessors`) are identical (`_normalize(in_d, 0, 20)`).<br>2. Feature 1 (`out_degree`) and Feature 6 (`num_successors`) are identical (`_normalize(out_d, 0, 20)`).<br>3. In static mode (`update_graph_features`, lines 616–617), Feature 27 (`num_path_constraints`) and Feature 35 (`max_constraint_depth`) are both set to normalized `guard_count` (`guard_count / 6.0` and `guard_count / 5.0`), which is already captured by Feature 28 (`guard_complexity`). |
| **GNN-02** | **Feature Group Dimensions in `paper.tex` Do Not Match Code** | `src/graph/feature_extractor.py:675-681` vs. `paper.tex:247-273` | `paper.tex` claims five 8-dimensional feature groups ($5 \times 8 = 40$). In `feature_extractor.py`, `FEATURE_GROUPS` has sizes `structural: 8` (`0..7`), `instruction: 6` (`8..13`), `semantic: 12` (`14..25`), `dataflow: 8` (`26..33`), `symbolic: 6` (`34..39`). |
| **GNN-03** | **Equations (1)–(4) in `paper.tex` Do Not Match `VulnGNN.forward()` or `trainer.py`** | `src/ml/gnn_model.py:132-238`, `src/ml/trainer.py:260-285` vs. `paper.tex:278-323` | 1. `VulnGNN` computes `0.5 * (x_fwd + x_bwd)` (average, not concatenation), adds residual `x + h`, and adds `0.25 * g_ctx[batch]` inside each layer (`gnn_model.py:209-227`).<br>2. `feature_gate` is applied *after* message passing (`x = x * self.feature_gate(x)`, line 234), not to raw input $\mathbf{x}_v$.<br>3. Classifier head is a 3-layer MLP (`128 -> 64 -> 32 -> 2`), not a single matrix $\mathbf{W}_{\text{cls}}$.<br>4. Temperature scaling $T$ is found via 40-point grid search `np.linspace(0.5, 3.0, 40)` (`trainer.py:267`), not L-BFGS. |
| **GNN-04** | **Missing Non-GNN & Standard GNN Baselines on Identical Splits** | `scripts/run_publication_experiments.py:424-472` | Current baselines in `run_publication_experiments.py` only compare against single-feature thresholds (`Heuristic_in_degree`, `Heuristic_has_unsafe_string`, etc.), a 2-layer 64-dim `MinimalGCN_Baseline`, and an uncalibrated `VulnGNN_SingleSeed`. Missing: **XGBoost (40-d node features)**, **MLP-only (no graph edges)**, **Unidirectional GraphSAGE (forward edges only)**, **GIN (Graph Isomorphism Network)**, **Random Ranking baseline**, and **Mean Reciprocal Rank (MRR)** / size-normalized ranking metrics. |

---

### 1.4 Dataset Construction & Ground-Truth Labeling Issues

| ID | Issue Summary | Source File & Lines | Verified Evidence |
| :--- | :--- | :--- | :--- |
| **DATA-01** | **`-fno-inline` Passed Across All Optimization Levels (`-O0`, `-O1`, `-O2`, `-Os`)** | `scripts/build_large_corpus.py:361`, `scripts/build_primevul_real_corpus.py:359` | Both corpus builders pass `-fno-inline` to `clang` even when compiling `-O2` and `-Os` binaries, invalidating the claim in `paper.tex` Section IV-C that the evaluation measures robustness against compiler function inlining at `-O2`/`-Os`. |
| **DATA-02** | **PrimeVul Isolated Function Stub Compilation Limitations Undocumented** | `scripts/build_primevul_real_corpus.py:257-391` | PrimeVul functions are compiled in isolation by auto-generating flat dummy `intptr_t` structs (`struct _u_any`), `#define MACRO(...) 1`, dummy symbol stubs (`long sym() { return 0; }`), and a stub `main()`. While this produces valid ARM64 Mach-O object code for the target function, it alters struct field offsets and interprocedural call contexts and must be rigorously documented and validated. |
| **DATA-03** | **Nearest-Block Fallback (`< 0x200` / `< 0x400`) in DWARF-to-CFG Labeling** | `scripts/build_large_corpus.py:417-425, 470-478`, `scripts/build_primevul_real_corpus.py:553-563` | When DWARF line addresses do not fall inside any lifted CFG node's `[addr, addr + size)` span, the script snaps the positive label to the nearest basic block within `0x200`–`0x400` bytes without recording how often exact vs. fallback matching occurred. |
| **DATA-04** | **Four `SysUtils-Prod` Binaries Are Identical macOS `xcrun` Wrapper Shims** | `scripts/build_large_corpus.py:55-60`, `benchmark_gnn_results.json:473-519` | On macOS, `/usr/bin/m4`, `/usr/bin/strings`, `/usr/bin/nm`, and `/usr/bin/size` are hardlinked `xcrun` wrapper stubs (all 4 yield identical 48-node, 47-edge, 68.1 KB graphs). The real ARM64 binaries reside in `/Library/Developer/CommandLineTools/usr/bin/{m4,strings,nm-classic,size-classic}`. |

---

## 2. FALSE OR UNVERIFIED AUDIT ALLEGATIONS (NUANCES & PARTIAL IMPLEMENTATIONS)

Per Step 1 instructions ("Do not blindly trust the audit. Independently verify every major allegation"), we identified four areas where the codebase is more nuanced than a surface reading of the paper suggests:

1. **Symbol Scrubbing on Stripped Mach-O Binaries Is Already Implemented (`src/graph/feature_extractor.py:130-154`):**
   - Although `BinaryLoader._parse_macho_stubs()` resolves dynamic imports via `LC_DYSYMTAB`, `feature_extractor.py` explicitly defines `_clean_api_name()` (lines 130–154) which rejects internal compiler/Juliet helper names (`good*`, `bad*`, `cwe*`, `printline`, `globalreturns*`, ` helper*`) unless the target is an external library import (`is_plt`, `is_simprocedure`, `__stubs`, or in `_KNOWN_EXTERNAL_APIS`). Thus, Juliet function names (`CWE121_..._bad`) do **not** leak into the 40-dimensional node features.
2. **Stratified 90-Binary Symbolic Benchmark Selector Already Exists in `scripts/benchmark_binaries.py` (`lines 294-370`):**
   - While `benchmark_symbolic_results.json` on disk was generated by an older run (37 binaries including 30 unstripped Juliet `CWE121` binaries), `scripts/benchmark_binaries.py` had already been updated on Nov 6 with `select_stratified_targets()` to sample 90 binaries (42 Juliet across 21 CWEs, 30 PrimeVul CVEs, 6 ARM64 micro-benchmarks, 1 multi-sink harness, and 11 system utilities) AND includes both Guided and Unguided runs (`lines 384-420`). However, it was never executed to completion after fixing the symbolic engine bugs (`SYM-01`, `SYM-02`, `SYM-03`, `SYM-04`).
3. **Juliet vs. PrimeVul vs. Zero-Shot Split Separation Already Exists in `benchmark_gnn_results.json` (`lines 615-755`):**
   - `scripts/run_publication_experiments.py` already computes separate metrics for `juliet_heldout_subset_test`, `primevul_heldout_subset_test`, `primevul_standalone_real_cve_test`, and `zero_shot_generalization`. The flaw was in `paper.tex` omitting the unfavorable splits/metrics (`clean_binary_fpr`, zero F1s), not a lack of split separation in the evaluation script itself.
4. **DWARF Line-Range Scoping for Juliet & PrimeVul Already Uses Function Symbol Bounds (`build_large_corpus.py:372-395`, `build_primevul_real_corpus.py:487-536`):**
   - In `build_large_corpus.py`, DWARF line table parsing is restricted to addresses inside `_bad` symbol address ranges (`bad_ranges`) and excludes shared harness lines (`main_linux.cpp`, `io.c`, `std_thread.c`) and call instructions (`bl`) to helper functions. In `build_primevul_real_corpus.py`, line-level diffs (`difflib.SequenceMatcher`) between `func_vuln` and `func_patch` are used when `target_func_patch` is available (755/792 vulnerable binaries = 95.3%), falling back to full-function labeling only when patch diff lines are empty.

---

## 3. CRITICAL BLOCKERS FOR PUBLICATION

Before `paper.tex` can be rewritten, the following **6 critical blockers** must be resolved in code and experiments:

1. **BLOCKER 1 — Broken Symbolic Constraint Variable Check (`SYM-01`) & Fabricated `[65]*40` Payloads (`SYM-02`):**
   - `c.leaf_asts` without `()` crashes `scan_vulnerabilities()` on legitimate SAT states, and `[65]*40` fabricates fake payloads when UNSAT/ERROR occurs.
2. **BLOCKER 2 — Mach-O Stub Hook Collision (`SYM-03`) & Absence of Live Native Crash Replay (`SYM-05`):**
   - `BinaryLoader` stub hooks currently clobber `printf` and `snprintf` taint propagation, and synthesized payloads are not verified by running the native binary to confirm a real crash (`SIGSEGV`/`SIGABRT`/`SIGBUS`) or controlled sink execution.
3. **BLOCKER 3 — Unimplemented Risk-Prioritized Symbolic Scheduler $\mathcal{H}(s)$ (`SYM-04`) & Missing Guided vs. Unguided Symbolic Benchmark at Scale:**
   - The symbolic engine must implement an actual priority worklist guided by node/function GNN risk scores $P_{\text{GNN}}(v)$ and path depth penalty $\lambda \cdot \text{Depth}(s)$, and must be evaluated head-to-head against unguided DFS/BFS exploration under identical step/time budgets on $\ge 90$ stratified binaries and $\ge 200$ held-out binaries.
4. **BLOCKER 4 — Duplicate Features (`GNN-01`) & Artificial `-fno-inline` Flag (`DATA-01`) + `xcrun` Shims (`DATA-04`):**
   - Features 5, 6, and 35 are redundant copies of Features 0, 1, and 27/28; `SysUtils-Prod` includes 4 `xcrun` shims; and compiler optimization robustness needs an explicit inline-enabled (`-O0`, `-O1`, `-O2`, `-Os` *without* `-fno-inline`) evaluation experiment.
5. **BLOCKER 5 — Missing Non-GNN (XGBoost, MLP) and GNN (Unidirectional SAGE, GIN) Baselines & Size-Normalized Ranking Metrics (`GNN-04`):**
   - Reviewers require proof that message passing outperforms a 40-feature XGBoost / MLP classifier and that bidirectional edges outperform unidirectional edges, plus size-normalized ranking metrics (MRR, Expected Random Top-$K$).
6. **BLOCKER 6 — Dishonest/Incomplete Reporting in `paper.tex` (`REP-01` through `REP-06`):**
   - Every table in `paper.tex` must be programmatically generated from verified JSON outputs, preserving `0.0000` F1 scores, reporting `Clean-Binary FPR` on every split, and aligning all equations and algorithms with the exact code.

---

## 4. PROPOSED ARCHITECTURE & CODE CHANGES

### 4.1 Step 2 — Scientific Reporting & Programmatic LaTeX Table Generator
- **New Script:** `scripts/generate_paper_tables.py`
  - Reads `benchmark_gnn_results.json` and `benchmark_symbolic_results.json` directly and emits verified LaTeX table macros/snippets (`research_paper/generated_tables.tex`) with zero manual editing.
  - Never replaces `0.0` with `---`; prints `0.0000` when `TP = 0` and `num_positive > 0`, and prints `N/A (0 pos)` only when `num_positive == 0`.
  - Includes `Clean-Binary FPR`, `MRR`, and `Random Top-K Baseline` in all localization tables.

### 4.2 Step 3 — Symbolic Engine Repair (`src/core/interfaces.py`, `src/core/binary_loader.py`, `src/core/property_engine.py`, `src/symbolic/z3_interface.py`)
1. **Fix `c.leaf_asts()` in `src/core/interfaces.py:480`:**
   - Change `for leaf in c.leaf_asts:` to `for leaf in (c.leaf_asts() if callable(getattr(c, 'leaf_asts', None)) else c.leaf_asts):`.
2. **Eliminate Fabricated `[65] * 40` Fallback Payloads (`src/core/interfaces.py:1312-1359`):**
   - Remove all `synth_bytes = [65] * 40` fallback blocks.
   - Properly classify each candidate state into `SAT`, `UNSAT`, `UNKNOWN` (timeout / budget exhausted), or `ERROR`.
   - Only synthesize concrete `exploit_bytes` when `solver_status == "SAT"` and Z3 returns a valid model over symbolic input variables (`stdin_input`, `arg0..arg3`, or `taint_*`). If `solver_status != "SAT"`, set `exploit_bytes = []` and `reproduce_cmd = None`.
3. **Fix Mach-O Stub Hook Taint Propagation (`src/core/binary_loader.py:152-193` & `src/core/property_engine.py:143-274`):**
   - In `BinaryLoader._get_simprocedure_for_name`:
     - Use `angr.SIM_PROCEDURES['libc']['printf']()`, `fprintf`, `puts`, `snprintf`, `sprintf` (or custom taint-propagating `SimProcedure` subclasses whose `.display_name` is preserved as `'printf'`, `'snprintf'`, `'sprintf'`), and propagate taint from format string / variadic arguments into `dst_ptr` in `SafeSnprintf`/`SafeSprintf`.
     - Ensure `stdin_input` bytes injected by `SymbolicEngine.inject_symbolic_input` are also registered in `state.vuln_tracker.taint_set` so `read(0, buf, n)` via `posix.stdin` automatically marks `stdin_input` bytes as tainted!
   - In `property_engine.py`: capture `read`/`recv`/`fgets` buffer pointer and length arguments in `track_simproc_before` (`BP_BEFORE`, before `x0` is overwritten by the return value) and inject taint in `track_simproc_after` (`BP_AFTER`).
4. **Implement Genuine Risk-Prioritized Symbolic State Scheduler $\mathcal{H}(s)$ (`src/core/interfaces.py`):**
   - Accept node-level GNN probability map `gnn_node_Chain / gnn_node_scores: Dict[int, float]` in addition to `gnn_vulnerable_functions`.
   - Precompute for each CFG node $u$ its maximum reachable GNN risk score $\max_{v \in \text{Reachable}(u)} P_{\text{GNN}}(v)$ over the static CFG (using reverse topological / bounded BFS reachability).
   - Replace the LIFO `stack.pop()` loop in `_run_trace()` with a deterministic `heapq` max-priority queue ordered by:
     $$\mathcal{H}(s) = \max_{v \in \text{Reachable}(\text{addr}(s))} P_{\text{GNN}}(v) - \lambda \cdot \text{Depth}(s)$$
     when `guided=True` (with $\lambda = 0.02$), vs. standard unguided FIFO/DFS exploration when `guided=False`.
   - Track and log scheduler telemetry: `states_explored`, `states_pruned`, `max_queue_size`, `steps_to_first_sat`, `time_to_first_sat`, and `solver_status_counts` (`SAT`, `UNSAT`, `UNKNOWN`, `ERROR`).
5. **Implement Independent Live Native Crash Replay (`src/core/interfaces.py`):**
   - Add `verify_live_crash(binary_path: str, payload: bytes, timeout_s: float = 2.0) -> Dict[str, Any]` which executes `subprocess.run([binary_path], input=payload, timeout=timeout_s)` in an isolated environment and records `return_code`, `signal` (`SIGSEGV=-11`, `SIGABRT=-6`, `SIGBUS=-10`, `SIGILL=-4`, `SIGFPE=-8`), `crashed: bool`, and `replay_status` (`CONFIRMED_CRASH`, `EXITED_NONZERO`, `EXITED_NORMAL`, `SKIPPED_FUNC_HARNESS`, `TIMEOUT`).
   - Note: For entry-point (`stdin`) findings, live replay pipes the witness directly to the binary's `stdin`. For isolated function-level findings (`arg0..arg3`) where `main()` does not read `stdin` (such as Juliet socket/rand variants or isolated library functions), record `replay_mode: "ENTRY_STDIN"` vs. `"FUNCTION_HARNESS"` honestly.

### 4.3 Step 4 — Dataset Reconstruction & Validation (`src/graph/feature_extractor.py`, `scripts/build_large_corpus.py`, `scripts/build_primevul_real_corpus.py`)
1. **Replace the 3 Duplicate Feature Dimensions in `src/graph/feature_extractor.py`:**
   - Replace Index 5 (`num_predecessors`, duplicate of `in_degree`) with **`dominator_tree_depth`**: normalized depth of the basic block in the CFG immediate-dominator tree (`nx.immediate_dominators(nx_graph, entry_addr)`).
   - Replace Index 6 (`num_successors`, duplicate of `out_degree`) with **`post_dominator_depth`** (or **`back_edge_count`**: number of incoming/outgoing CFG back-edges incident to the block, capturing loop latching structure distinct from simple out-degree).
   - Replace Index 35 (`max_constraint_depth`, duplicate of `num_path_constraints` in static mode) with **`branch_condition_complexity`**: static VEX IR comparison operator diversity and bit-width score (counting signed vs. unsigned comparisons `CmpLT32S`/`CmpLE64U`/`CmpNE`, cascaded bitwise `And`/`Or` guards in the block's VEX statements, and live dynamic AST depth when symbolic execution is active).
   - Update existing `.pt` graphs in-place (or via a fast migration script `scripts/update_dataset_features.py`) and verify zero duplicate feature columns across the entire corpus (checking pairwise Pearson correlation $\rho < 0.99$).
2. **Replace the 4 `xcrun` Shims in `SysUtils-Prod` (`scripts/build_large_corpus.py`):**
   - Resolve system binaries via `xcrun --find <name>` when `/usr/bin/<name>` is an `xcrun` stub (specifically `/Library/Developer/CommandLineTools/usr/bin/m4`, `strings`, `nm-classic`, `size-classic`), and rebuild `data/real_world_binaries/real_{m4,strings,nm,size}.bin` and `data/real_world_graphs/real_{m4,strings,nm,size}.pt`.
3. **Evaluate Compiler Optimizations Without `-fno-inline` & Validate DWARF-to-VEX Mapping:**
   - Create `scripts/validate_dataset_integrity.py` to:
     - Audit exact `[addr, addr+size)` DWARF line-to-VEX block matches vs. nearest-block fallback across all Juliet and PrimeVul graphs.
     - Compile a 200-binary multi-optimization benchmark (`-O0`, `-O1`, `-O2`, `-Os`) **without** `-fno-inline` to measure true inlining impact on CFG node count, DWARF label survival, and GNN localization accuracy.

### 4.4 Step 5 — GNN Baselines, Ablations & Metrics (`src/ml/gnn_model.py`, `src/ml/trainer.py`, `scripts/run_publication_experiments.py`)
1. **Add Model Architectures to `src/ml/gnn_model.py`:**
   - `MLPBaseline`: 3-layer MLP operating purely on the 40-d node features $\mathbf{x}_v$ with zero graph edges (tests whether message passing adds value over static block features).
   - `UnidirectionalVulnGNN`: GraphSAGE operating strictly on forward CFG edges $\mathcal{E}_{\text{fwd}}$ (tests whether reverse edges $\mathcal{E}_{\text{rev}}$ add value).
   - `GINVulnGNN`: 3-layer bidirectional Graph Isomorphism Network (`GINConv`) baseline alongside `SAGEConv` and `GATConv`.
2. **Add `XGBoost` Node Classifier Baseline in `scripts/run_publication_experiments.py`:**
   - Train `xgboost.XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.05, scale_pos_weight=...)` on the exact same 70% training split node features, calibrate threshold on the 15% validation split, and evaluate node F1, PR-AUC, ROC-AUC, Top-$K$, MRR, and Clean-Binary FPR on the identical 15% held-out test split (and separately on Juliet, PrimeVul, and Zero-Shot splits).
3. **Add Size-Normalized Ranking Metrics & Random Ranking Baseline:**
   - Compute analytical **Expected Random Top-$K$ Hit Rate** for each graph $G = (\mathcal{V}, \mathcal{E})$ with $N = |\mathcal{V}|$ nodes and $M = |\mathcal{V}_{\text{vuln}}|$ vulnerable nodes:
     $$P_{\text{rand}}(\text{Top-}K) = 1 - \frac{\binom{N - M}{K}}{\binom{N}{K}}$$
   - Compute **Mean Reciprocal Rank (MRR)**: $\frac{1}{|\mathcal{G}_{\text{vuln}}|} \sum_{G} \frac{1}{\text{rank}_1(G)}$ and **Normalized Rank Percentile**: $\frac{\text{rank}_1(G) - 1}{|\mathcal{V}(G)| - 1}$.

---

## 5. EXPERIMENT EXECUTION PLAN

All experiments will be executed deterministically (`seed=42`, plus 5-seed ensemble `[42, 100, 2026, 7, 99]`) in four sequential stages:

1. **Stage A — Unit & Regression Test Suite (`tests/test_all.py`, `tests/test_taint_exploit.py`, `tests/test_ere_engine.py`):**
   - Verify all 6 sample binaries (`cwe120`, `cwe134`, `cwe416`, `cwe476`, `cwe78`, `secure_program`) and `tests/test_benchmarks_binary`.
   - Confirm 0 `ERROR: 'method' object is not iterable`, 0 fabricated `[65]*40` payloads, working `printf`/`snprintf` taint detection, and working live crash replay.
2. **Stage B — Dataset Feature Upgrade & DWARF-to-VEX / Inlining Validation (`scripts/validate_dataset_integrity.py`):**
   - Recompute non-redundant 40-d features across all 2,616 Juliet graphs, 1,924 PrimeVul graphs, and 39 real-world `SysUtils-Prod` graphs (with real `m4`, `strings`, `nm`, `size` binaries).
   - Run the 200-binary `-O0/-O1/-O2/-Os` inline-enabled (`no -fno-inline`) compilation & evaluation experiment.
3. **Stage C — Comprehensive GNN & Baseline Benchmark (`scripts/run_publication_experiments.py`):**
   - Train and evaluate on identical splits:
     - Single-feature heuristics
     - Random Ranking baseline (analytical & Monte Carlo)
     - `XGBoost` (40-d node features)
     - `MLPBaseline` (40-d node features, no edges)
     - `MinimalGCN` (2-layer, 64-d)
     - `Unidirectional-GraphSAGE` (forward edges only)
     - `Bidirectional-GAT` (3-layer, 128-d)
     - `Bidirectional-GIN` (3-layer, 128-d)
     - `Bidirectional-GraphSAGE` (single seed + 5-seed ensemble)
   - Report all metrics separately for: (i) Unified Test Split, (ii) Juliet Held-Out Test Split, (iii) PrimeVul Held-Out Test Split, (iv) PrimeVul Standalone Real-CVE Split, (v) Zero-Shot Cross-Project Split, and (vi) `SysUtils-Prod` Clean Binaries.
   - Run architectural & feature-group ablations (`-Structural`, `-Instruction`, `-Semantic`, `-Dataflow`, `-Symbolic`, `-GlobalContext`, `-FeatureGate`, `-ReverseEdges`, `-FocalLoss`, `-TempScaling`).
4. **Stage D — Head-to-Head Guided vs. Unguided Symbolic Execution Benchmark (`scripts/benchmark_binaries.py`):**
   - **Tier 1 (Stratified 90-Binary Benchmark):** 42 Juliet binaries across 21 CWEs + 30 PrimeVul CVE binaries + 6 ARM64 micro-benchmarks + 1 multi-sink harness + 11 system utilities.
   - **Tier 2 (Expanded 200-Binary Held-Out Benchmark):** 200 held-out test binaries (140 Juliet held-out across 21 CWEs + 60 PrimeVul held-out CVE binaries) comparing **GNN-Guided ($\mathcal{H}(s)$ MaxHeap)** vs. **Unguided Symbolic Execution** under identical step budget (`max_steps=400`, per-binary timeout `25s`).
   - Record: `states_explored`, `steps_to_first_sat`, `wall_clock_time_s`, `sat_count`, `unsat_count`, `unknown_count`, `error_count`, `speedup_ratio`, `confirmed_native_crashes`, and bootstrap 95% confidence intervals.

---

## 6. ESTIMATED COMPUTATIONAL REQUIREMENTS (APPLE M4, 10 CORES, MPS GPU)

Based on measured timings on this machine:
- **Stage A (Unit & Regression Tests):** ~15 seconds.
- **Stage B (Feature Vector Update for 4,579 `.pt` Graphs + 4 System Binaries + 200-Binary Inline-Enabled Study):** ~4–6 minutes across 8 worker processes.
- **Stage C (GNN 5-Seed Ensemble + XGBoost + MLP + Unidirectional SAGE + GAT + GIN + Ablations + Federated Learning):** ~10–14 minutes on Apple M4 MPS/CPU.
- **Stage D (Guided vs. Unguided Symbolic Benchmark on 90 Stratified + 200 Held-Out Binaries):** ~18–25 minutes across parallel workers.
- **Total End-to-End Compute Wall-Clock Time:** **~35–45 minutes** (well within local execution capacity).

---

## 7. ORDERED IMPLEMENTATION ROADMAP

1. **Phase 1 (Current — Complete):** Codebase investigation, verification of all audit findings, reproduction of bugs, and creation of `RESEARCH_RECOVERY_PLAN.md`. *(Waiting for user approval to proceed.)*
2. **Phase 2 (Step 3 — Symbolic Engine Repair):**
   - Fix `c.leaf_asts()` in `src/core/interfaces.py`.
   - Remove `[65]*40` fabricated fallback payloads and implement strict `SAT`/`UNSAT`/`UNKNOWN`/`ERROR` accounting.
   - Fix `BinaryLoader` stub hook collision (`printf`/`snprintf`) and `stdin_input` taint registration.
   - Implement the $\mathcal{H}(s)$ `MaxHeap` risk-prioritized state scheduler and telemetry tracking.
   - Implement `verify_live_crash()` native crash replay verification.
   - Fix `tests/test_all.py` default binary resolution and run the full unit test suite to 100% pass.
3. **Phase 3 (Step 4 — Dataset Reconstruction & Validation):**
   - Replace duplicate features (indices 5, 6, 35) in `src/graph/feature_extractor.py` with `dominator_tree_depth`, `back_edge_count`, and `branch_condition_complexity`.
   - Replace the 4 `xcrun` wrapper shims in `SysUtils-Prod` with the true ARM64 binaries from `/Library/Developer/CommandLineTools/usr/bin/`.
   - Update `.pt` graphs, validate DWARF-to-VEX exact vs. fallback mapping rates, and run the 200-binary inline-enabled (`no -fno-inline`) compiler optimization experiment.
4. **Phase 4 (Step 5 — GNN Baselines & Ablations):**
   - Implement `XGBoost`, `MLPBaseline`, `UnidirectionalVulnGNN`, `GINVulnGNN`, random ranking baseline, and `MRR` / size-normalized metrics.
   - Execute `scripts/run_publication_experiments.py` and verify `benchmark_gnn_results.json`.
5. **Phase 5 (Step 6 — Symbolic Execution Benchmarks):**
   - Execute the 90-binary stratified benchmark and 200-binary held-out Guided vs. Unguided symbolic execution benchmark via `scripts/benchmark_binaries.py`, generating `benchmark_symbolic_results.json`.
6. **Phase 6 (Step 2 & Step 7 — Programmatic Reporting & Novelty Reassessment):**
   - Run `scripts/generate_paper_tables.py` to generate all LaTeX tables directly from JSON artifacts.
   - Document updated prior-art comparison and honest novelty scoping.
7. **Phase 7 (Step 8 — Manuscript Rewrite & Verification):**
   - Update `research_paper/paper.tex` so every equation, algorithm, table, figure, and claim strictly matches the verified code and experimental logs.

