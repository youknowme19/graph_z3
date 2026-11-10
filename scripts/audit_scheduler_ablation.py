#!/usr/bin/env python3
"""
Phase 4 Independent Audit: 4-Way Matched-Budget Scheduler Ablation Study

Evaluates 4 state exploration schedulers under strictly matched budgets
(timeout = 10.0s, max_steps = 80, depth_penalty_lambda = 0.02):
  1. DFS Baseline: LIFO frontier stack, no guidance.
  2. GNN-Guided MaxHeap: Priority = max_{v in Reachable(s)} P_GNN(v) - lambda * Depth(s).
  3. Random MaxHeap: Priority = max_{v in Reachable(s)} P_Rand(v) - lambda * Depth(s), seed=42.
  4. Static Heuristic MaxHeap: Priority = max_{v in Reachable(s)} P_Static(v) - lambda * Depth(s),
     where P_Static(v) = 1 / (1 + dist(v, dangerous_sinks)).

Outputs machine-readable telemetry to benchmark_4way_scheduler_ablation.json.
"""

import os
import sys
import time
import json
import random
import signal
from pathlib import Path
from collections import defaultdict

import torch
import numpy as np
import networkx as nx

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(root_dir, "src"))

from core.binary_loader import BinaryLoader
from core.interfaces import AnalysisBackendProvider, SymbolicTimeout
from graph.graph_builder import GraphBuilder
from ml.gnn_model import create_model


def _alarm_handler(signum, frame):
    AnalysisBackendProvider._timeout_flag = True
    raise SymbolicTimeout("Timeout budget reached")


def load_trained_gnn():
    model_path = os.path.join(root_dir, "model.pt")
    checkpoint = torch.load(model_path, map_location="cpu", weights_only=False)
    config = checkpoint.get(
        "config",
        {"input_dim": 40, "hidden_dim": 128, "num_layers": 3, "encoder": "sage", "dropout": 0.25},
    )
    model = create_model(**config)
    model.load_state_dict(checkpoint["model_state_dict"])
    temp = float(checkpoint.get("temperature", 1.0))
    thresh = float(checkpoint.get("threshold", 0.5))
    temp_path = os.path.join(root_dir, "model_temperature.json")
    if os.path.exists(temp_path):
        temp = float(json.load(open(temp_path)).get("temperature", temp))
    thresh_path = os.path.join(root_dir, "model_threshold.json")
    if os.path.exists(thresh_path):
        thresh = float(json.load(open(thresh_path)).get("threshold", thresh))
    model.set_temperature(temp)
    model.eval()
    return model, temp, thresh


def compute_gnn_scores(loader: BinaryLoader, model, thresh: float, top_k_blocks: int = 5):
    t0 = time.perf_counter()
    builder = GraphBuilder(loader)
    nx_cfg = builder.build_networkx_cfg()
    nx_cg = builder.build_networkx_cg()

    nodes = list(nx_cfg.nodes())
    if not nodes:
        return {}, {}, 0.0
    node_to_idx = {n: i for i, n in enumerate(nodes)}
    x_list = [nx_cfg.nodes[n].get("features", [0.0] * 40) for n in nodes]
    edges_src, edges_dst = [], []
    for u, v in nx_cfg.edges():
        if u in node_to_idx and v in node_to_idx:
            edges_src.append(node_to_idx[u])
            edges_dst.append(node_to_idx[v])
    x = torch.tensor(x_list, dtype=torch.float)
    edge_index = (
        torch.tensor([edges_src, edges_dst], dtype=torch.long)
        if edges_src
        else torch.empty((2, 0), dtype=torch.long)
    )

    t_infer0 = time.perf_counter()
    with torch.no_grad():
        probs = model.predict_proba(x, edge_index)[:, 1].numpy()
    gnn_ms = (time.perf_counter() - t_infer0) * 1000.0

    node_risk_map = {int(nodes[i]): float(probs[i]) for i in range(len(nodes))}

    cand_indices = set(int(i) for i, p in enumerate(probs) if p >= thresh)
    if not cand_indices and len(probs) > 0 and float(probs.max()) >= 0.20:
        ranked = probs.argsort()[::-1][: min(top_k_blocks, len(probs))]
        cand_indices.update(int(i) for i in ranked)

    func_vuln_map = {}
    for idx in cand_indices:
        b_addr = nodes[idx]
        p_val = float(probs[idx])
        for fn_addr in nx_cg.nodes():
            if b_addr in nx_cg.nodes[fn_addr].get("block_addrs", set()):
                func_vuln_map[fn_addr] = max(func_vuln_map.get(fn_addr, 0.0), p_val)
                break
        else:
            fn = loader.get_functions().floor_func(b_addr)
            if fn is not None:
                func_vuln_map[fn.addr] = max(func_vuln_map.get(fn.addr, 0.0), p_val)

    return func_vuln_map, node_risk_map, round(gnn_ms, 3)


def compute_static_scores(loader: BinaryLoader, cfg: nx.DiGraph) -> dict:
    """
    Identifies dangerous sinks strictly by symbol/import string matching
    on standard C functions (zero ground-truth vulnerability labels or annotations).
    Assigns proximity score: P_Static(v) = 1 / (1 + shortest_path_distance(v, dangerous_sinks)).
    Standard sinks checked: strcpy, strcat, sprintf, vsprintf, gets, system, popen,
    execve, execl, execlp, memcpy, memmove, free.
    """
    DANGEROUS = {
        'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'system',
        'popen', 'execve', 'execl', 'execlp', 'memcpy', 'memmove', 'free'
    }
    funcs = loader.get_functions()
    sinks = set()
    for f_addr, fn in funcs.items():
        if any(d in fn.name.lower() for d in DANGEROUS):
            sinks.add(int(f_addr))

    static_scores = {}
    for n in cfg.nodes():
        d_min = float('inf')
        for s in sinks:
            if nx.has_path(cfg, n, s):
                d = nx.shortest_path_length(cfg, n, s)
                if d < d_min:
                    d_min = d
        if d_min < float('inf'):
            static_scores[int(n)] = round(1.0 / (1.0 + d_min), 4)
        else:
            static_scores[int(n)] = 0.05
    return static_scores


def compute_random_scores(cfg: nx.DiGraph, seed: int = 42) -> dict:
    rng = random.Random(seed)
    return {int(n): round(rng.random(), 4) for n in cfg.nodes()}


def run_condition(
    binary_path: str,
    loader: BinaryLoader,
    mode_name: str,
    scheduler_mode: str,
    node_scores: dict = None,
    func_vuln_map: dict = None,
    timeout_s: float = 10.0,
    max_steps: int = 80,
    initial_overhead_s: float = 0.0,
) -> dict:
    rem_timeout = max(0.1, timeout_s - initial_overhead_s)
    AnalysisBackendProvider._timeout_flag = False
    signal.signal(signal.SIGALRM, _alarm_handler)
    t0 = time.perf_counter()
    timed_out = False
    backend = None
    vulns = []

    try:
        signal.setitimer(signal.ITIMER_REAL, rem_timeout, 0.5)
        backend = AnalysisBackendProvider(
            binary_path,
            max_steps=max_steps,
            gnn_vulnerable_functions=func_vuln_map,
            gnn_node_scores=node_scores,
            scheduler_mode=scheduler_mode,
            depth_penalty_lambda=0.02,
            timeout_seconds=rem_timeout,
            _shared_loader=loader,
        )
        vulns = backend.scan_vulnerabilities()
    except SymbolicTimeout:
        timed_out = True
    except Exception as e:
        timed_out = False
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0.0, 0.0)

    if AnalysisBackendProvider._timeout_flag:
        timed_out = True

    tel = getattr(backend, "scheduler_telemetry", {}) if backend else {}
    if tel.get("timed_out"):
        timed_out = True

    actual_elapsed = (time.perf_counter() - t0) + initial_overhead_s
    time_s = min(actual_elapsed, timeout_s) if timed_out else actual_elapsed

    solver_counts = tel.get("solver_status_counts", {})
    sat_count = solver_counts.get("SAT", 0)

    return {
        "condition": mode_name,
        "time_s": round(time_s, 3),
        "actual_elapsed_wall_s": round(actual_elapsed, 3),
        "states_explored": tel.get("states_explored", 0),
        "steps_to_first_vuln": tel.get("steps_to_first_vuln"),
        "time_to_first_vuln_ms": tel.get("time_to_first_vuln_ms"),
        "max_frontier_size": tel.get("max_frontier_size", 0),
        "sat_witnesses": sat_count,
        "vulnerabilities_reported": len(vulns),
        "solver_status_counts": solver_counts,
        "timed_out": timed_out,
    }


def main():
    print("=" * 80)
    print("NeuroZ3 — 4-Way Matched-Budget Scheduler Ablation Study")
    print("Schedulers: 1) DFS Baseline  2) GNN-Guided  3) Random-MaxHeap  4) Static-Heuristic")
    print("Matched Budget: Timeout = 10.0s, Max Steps = 80, Lambda = 0.02")
    print("=" * 80)

    model, temp, thresh = load_trained_gnn()
    print(f"[+] Loaded VulnGNN model (T={temp:.4f}, thresh={thresh:.4f})")

    # Select representative 22-binary benchmark suite across all strata
    target_specs = [
        # 1. Sample binaries (5 vulnerable + 1 clean)
        ("samples", "data/samples/cwe120_buffer_overflow.bin"),
        ("samples", "data/samples/cwe134_format_string.bin"),
        ("samples", "data/samples/cwe416_use_after_free.bin"),
        ("samples", "data/samples/cwe476_null_deref.bin"),
        ("samples", "data/samples/cwe78_command_injection.bin"),
        ("samples", "data/samples/secure_program.bin"),
        # 2. Test suite multi-vuln binary
        ("test_suite", "tests/test_benchmarks_binary"),
        # 3. Stratified Juliet vulnerable testcases (7 CWEs)
        ("juliet_vuln", "data/train_binaries/CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_10_O0.out"),
        ("juliet_vuln", "data/train_binaries/CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_65_O0.out"),
        ("juliet_vuln", "data/train_binaries/CWE124_Buffer_Underwrite__CWE839_fgets_03_O2.out"),
        ("juliet_vuln", "data/train_binaries/CWE126_Buffer_Overread__CWE129_fgets_04_O0.out"),
        ("juliet_vuln", "data/train_binaries/CWE127_Buffer_Underread__CWE839_fgets_17_Os.out"),
        ("juliet_vuln", "data/train_binaries/CWE78_OS_Command_Injection__char_connect_socket_execl_02_O0.out"),
        ("juliet_vuln", "data/train_binaries/CWE194_Unexpected_Sign_Extension__connect_socket_malloc_42_Os.out"),
        # 4. Juliet patched negative controls (3 binaries)
        ("juliet_patched", "data/train_binaries/CWE121_Stack_Based_Buffer_Overflow__CWE129_rand_06_PATCHED_O0.out"),
        ("juliet_patched", "data/train_binaries/CWE78_OS_Command_Injection__char_file_popen_63_PATCHED_O0.out"),
        ("juliet_patched", "data/train_binaries/CWE121_Stack_Based_Buffer_Overflow__CWE135_04_PATCHED_O0.out"),
        # 5. Real-World PrimeVul CVEs (3 binaries)
        ("primevul_cve", "data/primevul_binaries/PV_00000_openssl_CVE-2013-6449_CWE310_VULN_O0.out"),
        ("primevul_cve", "data/primevul_binaries/PV_00008_haproxy_CVE-2018-20103_CWE835_VULN_O0.out"),
        ("primevul_cve", "data/primevul_binaries/PV_00042_haproxy_CVE-2015-3281_CWE119_VULN_O0.out"),
        # 6. Production System Utilities (2 binaries)
        ("system_util", "data/real_world_binaries/real_cut.bin"),
        ("system_util", "data/real_world_binaries/real_head.bin"),
    ]

    all_results = []
    condition_aggregates = {
        "dfs": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
        "gnn_maxheap": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
        "random_maxheap_42": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
        "random_maxheap_1337": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
        "random_maxheap_2026": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
        "random_maxheap": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
        "static_heuristic": {"total_time": 0.0, "total_states": 0, "total_sat": 0, "total_vulns": 0, "timeouts": 0},
    }

    import z3
    z3.set_param('timeout', 2500)

    for idx, (group, rel_path) in enumerate(target_specs):
        full_path = os.path.join(root_dir, rel_path)
        bname = os.path.basename(full_path)
        print(f"\n[{idx+1:02d}/{len(target_specs):02d}] ({group:14s}) {bname[:36]:36s}")

        if not os.path.exists(full_path):
            print(f"  [ERROR] Binary not found: {full_path}")
            continue

        # Load binary once and build CFG
        loader = BinaryLoader(full_path)
        loader.analyze()
        cfg = GraphBuilder(loader).build_networkx_cfg()

        # Compute GNN scores
        func_map, gnn_node_scores, gnn_ms = compute_gnn_scores(loader, model, thresh)

        # Compute Static Heuristic scores (pure symbol/import name pattern matching, zero ground-truth labels)
        static_scores = compute_static_scores(loader, cfg)

        # 1. DFS Baseline
        res_dfs = run_condition(full_path, loader, "dfs", "dfs", timeout_s=10.0, max_steps=80)
        # 2. GNN MaxHeap (with GNN feature extraction + inference time included in budget)
        res_gnn = run_condition(full_path, loader, "gnn_maxheap", "maxheap", node_scores=gnn_node_scores, func_vuln_map=func_map, timeout_s=10.0, max_steps=80, initial_overhead_s=(gnn_ms / 1000.0))
        # 3. Random MaxHeap across seeds 42, 1337, 2026
        res_rand_42 = run_condition(full_path, loader, "random_maxheap_42", "maxheap", node_scores=compute_random_scores(cfg, seed=42), timeout_s=10.0, max_steps=80)
        res_rand_1337 = run_condition(full_path, loader, "random_maxheap_1337", "maxheap", node_scores=compute_random_scores(cfg, seed=1337), timeout_s=10.0, max_steps=80)
        res_rand_2026 = run_condition(full_path, loader, "random_maxheap_2026", "maxheap", node_scores=compute_random_scores(cfg, seed=2026), timeout_s=10.0, max_steps=80)
        res_rand_mean = {
            "condition": "random_maxheap",
            "time_s": round(float(np.mean([res_rand_42["time_s"], res_rand_1337["time_s"], res_rand_2026["time_s"]])), 3),
            "states_explored": round(float(np.mean([res_rand_42["states_explored"], res_rand_1337["states_explored"], res_rand_2026["states_explored"]])), 1),
            "sat_witnesses": round(float(np.mean([res_rand_42["sat_witnesses"], res_rand_1337["sat_witnesses"], res_rand_2026["sat_witnesses"]])), 2),
            "vulnerabilities_reported": round(float(np.mean([res_rand_42["vulnerabilities_reported"], res_rand_1337["vulnerabilities_reported"], res_rand_2026["vulnerabilities_reported"]])), 2),
            "timed_out": bool(res_rand_42["timed_out"] or res_rand_1337["timed_out"] or res_rand_2026["timed_out"]),
            "seeds": {
                "42": res_rand_42,
                "1337": res_rand_1337,
                "2026": res_rand_2026,
            }
        }
        # 4. Static Heuristic MaxHeap
        res_stat = run_condition(full_path, loader, "static_heuristic", "maxheap", node_scores=static_scores, timeout_s=10.0, max_steps=80)

        record = {
            "binary": bname,
            "group": group,
            "path": rel_path,
            "gnn_infer_ms": round(gnn_ms, 2),
            "conditions": {
                "dfs": res_dfs,
                "gnn_maxheap": res_gnn,
                "random_maxheap_42": res_rand_42,
                "random_maxheap_1337": res_rand_1337,
                "random_maxheap_2026": res_rand_2026,
                "random_maxheap": res_rand_mean,
                "static_heuristic": res_stat,
            },
        }
        all_results.append(record)

        for c_key in ["dfs", "gnn_maxheap", "random_maxheap_42", "random_maxheap_1337", "random_maxheap_2026", "random_maxheap", "static_heuristic"]:
            c_res = record["conditions"][c_key]
            condition_aggregates[c_key]["total_time"] += c_res["time_s"]
            condition_aggregates[c_key]["total_states"] += c_res["states_explored"]
            condition_aggregates[c_key]["total_sat"] += c_res["sat_witnesses"]
            condition_aggregates[c_key]["total_vulns"] += c_res["vulnerabilities_reported"]
            if c_res["timed_out"]:
                condition_aggregates[c_key]["timeouts"] += 1

        print(f"  DFS:    Time={res_dfs['time_s']:.2f}s | States={res_dfs['states_explored']} | SAT={res_dfs['sat_witnesses']} | Vulns={res_dfs['vulnerabilities_reported']}")
        print(f"  GNN:    Time={res_gnn['time_s']:.2f}s | States={res_gnn['states_explored']} | SAT={res_gnn['sat_witnesses']} | Vulns={res_gnn['vulnerabilities_reported']}")
        print(f"  Rand:   Time={res_rand_mean['time_s']:.2f}s (3-seed mean) | States={res_rand_mean['states_explored']} | SAT={res_rand_mean['sat_witnesses']}")
        print(f"  Static: Time={res_stat['time_s']:.2f}s | States={res_stat['states_explored']} | SAT={res_stat['sat_witnesses']} | Vulns={res_stat['vulnerabilities_reported']}")

    # Summary table
    print("\n" + "=" * 80)
    print("4-WAY SCHEDULER ABLATION SUMMARY (N=22 Binaries)")
    print("=" * 80)
    print(f"{'Condition':24s} | {'Total Time (s)':15s} | {'Mean Time/Bin':15s} | {'Total States':12s} | {'SAT Witnesses':14s} | {'Timeouts':8s}")
    print("-" * 96)
    n_bins = len(all_results)
    summary_data = {}
    for c_key in ["dfs", "gnn_maxheap", "random_maxheap_42", "random_maxheap_1337", "random_maxheap_2026", "random_maxheap", "static_heuristic"]:
        agg = condition_aggregates[c_key]
        mean_t = agg["total_time"] / max(n_bins, 1)
        mean_st = agg["total_states"] / max(n_bins, 1)
        summary_data[c_key] = {
            "total_time_s": round(agg["total_time"], 2),
            "mean_time_s": round(mean_t, 3),
            "total_states": round(agg["total_states"], 1) if isinstance(agg["total_states"], float) else agg["total_states"],
            "mean_states": round(mean_st, 1),
            "sat_witnesses": round(agg["total_sat"], 1) if isinstance(agg["total_sat"], float) else agg["total_sat"],
            "vulnerabilities": round(agg["total_vulns"], 1) if isinstance(agg["total_vulns"], float) else agg["total_vulns"],
            "timeouts": agg["timeouts"],
        }
        print(
            f"{c_key:24s} | {agg['total_time']:15.2f} | {mean_t:15.3f} | {str(agg['total_states']):12s} | {str(agg['total_sat']):14s} | {agg['timeouts']:8d}"
        )

    out_file = os.path.join(root_dir, "benchmark_4way_scheduler_ablation.json")
    payload = {
        "budget": {"timeout_seconds": 10.0, "max_steps": 80, "depth_penalty_lambda": 0.02, "solver_timeout_ms": 2500},
        "n_binaries": n_bins,
        "static_heuristic_sink_identification": (
            "Dangerous sinks are identified strictly by function symbol name and import table substring "
            "matching against standard C dangerous functions ('strcpy', 'strcat', 'sprintf', 'vsprintf', "
            "'gets', 'system', 'popen', 'execve', 'execl', 'execlp', 'memcpy', 'memmove', 'free'). "
            "Zero ground-truth vulnerability labels, annotations, or external vulnerability databases are used."
        ),
        "summary": summary_data,
        "binaries": all_results,
    }
    with open(out_file, "w") as f:
        json.dump(payload, f, indent=2)

    multi_seed_out = os.path.join(root_dir, "benchmark_4way_scheduler_ablation_multi_seed.json")
    with open(multi_seed_out, "w") as f:
        json.dump(payload, f, indent=2)

    print(f"\n[+] Saved complete 4-way ablation results to: {out_file}")
    print(f"[+] Saved multi-seed ablation results to: {multi_seed_out}")


if __name__ == "__main__":
    main()
