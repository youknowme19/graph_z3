#!/usr/bin/env python3
"""
Comprehensive Neuro-Symbolic Verification & Z3 Exploit Synthesis Benchmark
==========================================================================
Benchmarks AnalysisBackendProvider, VulnGNN risk-prioritized pre-filtering,
angr CFG recovery, symbolic execution, Z3 SMT constraint solving, and exploit
primitive classification across real compiled stripped binaries:
  1. Target Sample Suite (data/samples/*.bin, including secure_program.bin)
  2. Multi-Function Exploit Verification Suite (tests/test_benchmarks_binary)
  3. Stratified Multi-CWE Stripped Binaries (42 binaries across 21 CWEs + patched controls)
  4. Real-World Open-Source CVE Stripped Binaries (30 PrimeVul pre-patch & post-patch binaries)
  5. Production macOS/BSD System Binaries (11 utilities: bzip2, gzip, sed, patch, diff, hexdump, sort, uniq, tr, wc, cut)

Compares Unguided Symbolic Execution (DFS baseline) vs. GNN-Guided Neuro-Symbolic Verification (MaxHeap).
"""

import os
import sys
import time
import json
import signal
import hashlib
from pathlib import Path
from collections import defaultdict

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import numpy as np
import torch
from src.core.binary_loader import BinaryLoader
from src.graph.graph_builder import GraphBuilder
from src.ml.gnn_model import create_model
from src.core.interfaces import AnalysisBackendProvider


class SymbolicTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise SymbolicTimeout("Symbolic exploration cap reached")


def get_file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()


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


def compute_gnn_func_targets(loader: BinaryLoader, model, thresh: float, top_k_blocks: int = 5):
    t0 = time.perf_counter()
    builder = GraphBuilder(loader)
    nx_cfg = builder.build_networkx_cfg()
    nx_cg = builder.build_networkx_cg()

    nodes = list(nx_cfg.nodes())
    if not nodes:
        return {}, {}, 0, 0, 0.0
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

    t_gnn0 = time.perf_counter()
    with torch.no_grad():
        probs = model.predict_proba(x, edge_index)[:, 1].numpy()
    gnn_ms = (time.perf_counter() - t_gnn0) * 1000.0

    # Node-level risk map for MaxHeap scheduler priority scoring H(s)
    node_risk_map = {int(nodes[i]): float(probs[i]) for i in range(len(nodes))}

    # Select blocks exceeding calibrated threshold OR Top-K highest-risk blocks (when max prob >= 0.20)
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

    total_user_funcs = sum(
        1
        for f in loader.get_functions().values()
        if not f.is_plt and not f.is_simprocedure and f.size > 20 and not f.name.startswith("_start")
    )
    _ = time.perf_counter() - t0
    return func_vuln_map, node_risk_map, len(cand_indices), total_user_funcs, round(gnn_ms, 3)


def benchmark_single_binary(binary_path: str, model, thresh: float, max_steps: int = 100, compare_unguided: bool = True) -> dict:
    name = os.path.basename(binary_path)
    file_size = os.path.getsize(binary_path)
    sha256 = get_file_sha256(binary_path)

    result = {
        "filename": name,
        "path": binary_path,
        "size_bytes": file_size,
        "sha256": sha256,
        "status": "SUCCESS",
        "error": None,
        "cfg_nodes": 0,
        "cfg_edges": 0,
        "num_functions": 0,
        "user_functions": 0,
        "gnn_flagged_blocks": 0,
        "gnn_flagged_functions": 0,
        "gnn_infer_ms": 0.0,
        "gnn_guided_time_s": 0.0,
        "gnn_guided_states": 0,
        "gnn_guided_steps_to_vuln": None,
        "gnn_guided_time_to_vuln_ms": None,
        "gnn_guided_max_frontier": 0,
        "gnn_guided_solver_counts": {},
        "gnn_guided_timed_out": False,
        "unguided_time_s": None,
        "unguided_states": None,
        "unguided_steps_to_vuln": None,
        "unguided_time_to_vuln_ms": None,
        "unguided_max_frontier": None,
        "unguided_solver_counts": None,
        "unguided_timed_out": None,
        "unguided_vuln_count": None,
        "speedup_ratio": None,
        "state_reduction_ratio": None,
        "state_reduction_pct": None,
        "steps_to_vuln_reduction_ratio": None,
        "time_to_vuln_speedup": None,
        "analysis_time_s": 0.0,
        "vulnerabilities": [],
        "vuln_count": 0,
        "vuln_types": [],
        "solver_sat_count": 0,
        "avg_solver_time_ms": 0.0,
        "peak_cvss": 0.0,
        "composite_risk_score": 0.0,
        "mitigations": [],
        "exploit_primitives": [],
        "verified_live_crashes": 0,
    }

    t_load0 = time.perf_counter()
    try:
        loader = BinaryLoader(binary_path)
        loader.analyze()
        load_time_s = time.perf_counter() - t_load0

        cfg = loader.get_cfg()
        if cfg is not None:
            result["cfg_nodes"] = len(cfg.graph.nodes())
            result["cfg_edges"] = len(cfg.graph.edges())
        funcs = loader.get_functions()
        if funcs is not None:
            result["num_functions"] = len(funcs)

        func_vuln_map, node_risk_map, n_cand_blocks, total_ufuncs, gnn_ms = compute_gnn_func_targets(loader, model, thresh)
        result["user_functions"] = total_ufuncs
        result["gnn_flagged_blocks"] = n_cand_blocks
        result["gnn_flagged_functions"] = len(func_vuln_map)
        result["gnn_infer_ms"] = gnn_ms

        # 1. GNN-Guided Neuro-Symbolic Verification (MaxHeap + risk priority scoring)
        signal.signal(signal.SIGALRM, _alarm_handler)
        t_g0 = time.perf_counter()
        vulns = []
        guided_backend = None
        guided_timed_out = False
        try:
            signal.alarm(15)
            guided_map = func_vuln_map if func_vuln_map else {-1: False}
            guided_backend = AnalysisBackendProvider(
                binary_path,
                max_steps=max_steps,
                gnn_vulnerable_functions=guided_map,
                gnn_node_scores=node_risk_map,
                scheduler_mode="maxheap",
                depth_penalty_lambda=0.02,
                timeout_seconds=15.0,
                _shared_loader=loader,
            )
            vulns = guided_backend.scan_vulnerabilities()
        except SymbolicTimeout:
            guided_timed_out = True
        finally:
            signal.alarm(0)
        guided_tel = getattr(guided_backend, "scheduler_telemetry", {}) if guided_backend else {}
        if guided_tel.get("timed_out"):
            guided_timed_out = True
        guided_sym_s = 15.0 if guided_timed_out else (time.perf_counter() - t_g0)
        total_guided_s = load_time_s + (gnn_ms / 1000.0) + guided_sym_s
        result["gnn_guided_time_s"] = round(total_guided_s, 3)
        result["analysis_time_s"] = round(total_guided_s, 3)
        result["gnn_guided_timed_out"] = guided_timed_out
        result["gnn_guided_states"] = guided_tel.get("states_explored", 0)
        result["gnn_guided_steps_to_vuln"] = guided_tel.get("steps_to_first_vuln")
        result["gnn_guided_time_to_vuln_ms"] = guided_tel.get("time_to_first_vuln_ms")
        result["gnn_guided_max_frontier"] = guided_tel.get("max_frontier_size", 0)
        result["gnn_guided_solver_counts"] = guided_tel.get("solver_status_counts", {})
        result["verified_live_crashes"] = guided_tel.get("verified_exploits_count", 0)

        # 2. Unguided Symbolic Execution baseline (standard DFS exploration)
        if compare_unguided:
            t_u0 = time.perf_counter()
            u_vulns = []
            u_timed_out = False
            unguided_backend = None
            try:
                signal.alarm(15)
                unguided_backend = AnalysisBackendProvider(
                    binary_path,
                    max_steps=max_steps,
                    gnn_vulnerable_functions=None,
                    gnn_node_scores=None,
                    scheduler_mode="dfs",
                    timeout_seconds=15.0,
                    _shared_loader=loader,
                )
                u_vulns = unguided_backend.scan_vulnerabilities()
            except SymbolicTimeout:
                u_timed_out = True
            finally:
                signal.alarm(0)
            unguided_tel = getattr(unguided_backend, "scheduler_telemetry", {}) if unguided_backend else {}
            if unguided_tel.get("timed_out"):
                u_timed_out = True
            unguided_sym_s = 15.0 if u_timed_out else (time.perf_counter() - t_u0)
            total_unguided_s = load_time_s + unguided_sym_s
            unguided_tel = getattr(unguided_backend, "scheduler_telemetry", {}) if unguided_backend else {}
            u_states = unguided_tel.get("states_explored", 0)
            g_states = result["gnn_guided_states"]
            result["unguided_time_s"] = round(total_unguided_s, 3)
            result["unguided_timed_out"] = u_timed_out
            result["unguided_vuln_count"] = len(u_vulns)
            result["unguided_states"] = u_states
            result["unguided_steps_to_vuln"] = unguided_tel.get("steps_to_first_vuln")
            result["unguided_time_to_vuln_ms"] = unguided_tel.get("time_to_first_vuln_ms")
            result["unguided_max_frontier"] = unguided_tel.get("max_frontier_size", 0)
            result["unguided_solver_counts"] = unguided_tel.get("solver_status_counts", {})
            result["speedup_ratio"] = round(total_unguided_s / max(total_guided_s, 1e-4), 2)
            result["state_reduction_ratio"] = round(u_states / max(g_states, 1), 2)
            result["state_reduction_pct"] = round((1.0 - (g_states / max(u_states, 1))) * 100, 2)
            if result["unguided_steps_to_vuln"] is not None and result["gnn_guided_steps_to_vuln"] is not None:
                result["steps_to_vuln_reduction_ratio"] = round(result["unguided_steps_to_vuln"] / max(result["gnn_guided_steps_to_vuln"], 1), 2)
            if result["unguided_time_to_vuln_ms"] is not None and result["gnn_guided_time_to_vuln_ms"] is not None:
                result["time_to_vuln_speedup"] = round(result["unguided_time_to_vuln_ms"] / max(result["gnn_guided_time_to_vuln_ms"], 1e-4), 2)

        result["vuln_count"] = len(vulns)
        result["vuln_types"] = sorted(list(set(v.get("vuln_type") for v in vulns if v.get("vuln_type"))))

        sat_count = 0
        solver_times = []
        cvss_scores = []
        primitives = []
        all_mitigations = set()
        cleaned_vulns = []

        for v in vulns:
            v_info = {
                "vuln_type": v.get("vuln_type"),
                "severity": v.get("vuln_severity"),
                "address": v.get("address"),
                "function": v.get("function_name"),
                "details": v.get("vuln_details"),
                "solver_status": v.get("solver_status"),
                "solver_time_ms": round(v.get("solver_time_ms", 0.0), 3),
                "crash_length": v.get("crash_length", 0),
                "exploit_verified": bool(v.get("exploit_verified", False)),
                "crash_classification": v.get("crash_verification", {}).get("classification"),
            }
            if v.get("solver_status") == "SAT":
                sat_count += 1
            if v.get("solver_time_ms") is not None and v.get("solver_time_ms", 0.0) > 0:
                solver_times.append(v["solver_time_ms"])

            ep = v.get("exploit_primitive") or {}
            if ep.get("title"):
                v_info["exploit_title"] = ep.get("title")
                v_info["exploit_type"] = ep.get("primitive_type")
                v_info["cvss"] = ep.get("cvss_base_score", 0.0)
                v_info["reliability"] = ep.get("reliability")
                cvss_scores.append(ep.get("cvss_base_score", 0.0))
                primitives.append(ep.get("primitive_type"))
                for m in ep.get("mitigations_present", []):
                    all_mitigations.add(m)
            cleaned_vulns.append(v_info)

        result["vulnerabilities"] = cleaned_vulns
        result["solver_sat_count"] = sat_count
        result["avg_solver_time_ms"] = round(sum(solver_times) / len(solver_times), 3) if solver_times else 0.0
        result["peak_cvss"] = max(cvss_scores) if cvss_scores else 0.0
        result["composite_risk_score"] = round(
            0.7 * (max(cvss_scores) if cvss_scores else 0.0)
            + 0.3 * (sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0),
            2,
        )
        result["exploit_primitives"] = sorted(list(set(primitives)))
        result["mitigations"] = sorted(list(all_mitigations))

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        result["analysis_time_s"] = round(time.perf_counter() - t_load0, 3)

    return result


def select_stratified_targets():
    targets = []

    # 1. All 6 sample binaries (5 vulnerable CWEs + 1 secure_program.bin) - all paired
    samples_dir = Path(root_dir) / "data" / "samples"
    for p in sorted(samples_dir.glob("*.bin")):
        if not p.name.startswith("._"):
            targets.append(("samples", str(p), True))

    # 2. Multi-vuln benchmark suite binary - paired
    bench_bin = Path(root_dir) / "tests" / "test_benchmarks_binary"
    if bench_bin.exists():
        targets.append(("test_suite", str(bench_bin), True))

    # 3. Stratified Multi-CWE Juliet stripped binaries (21 CWEs: 21 vulnerable + 21 patched controls = 42 binaries)
    train_dir = Path(root_dir) / "data" / "train_binaries"
    by_cwe_vuln = defaultdict(list)
    by_cwe_patched = defaultdict(list)
    for p in sorted(train_dir.glob("*.out")):
        if p.name.startswith("._"):
            continue
        cwe = p.name.split("_")[0]
        if "_PATCHED_" in p.name:
            by_cwe_patched[cwe].append(p)
        else:
            by_cwe_vuln[cwe].append(p)

    def _prefer_stdin_or_direct(plist):
        ranked = sorted(
            plist,
            key=lambda x: (
                0 if any(k in x.name.lower() for k in ("fgets", "console", "fscanf", "malloc", "char_type", "memcpy", "strcpy", "binary_if")) else 1,
                x.name,
            ),
        )
        return ranked

    for cwe in sorted(by_cwe_vuln.keys()):
        v_list = _prefer_stdin_or_direct(by_cwe_vuln[cwe])
        # All 21 vulnerable Juliet CWE testcases paired head-to-head
        targets.append(("multi_cwe_vuln", str(v_list[0]), True))
        if by_cwe_patched[cwe]:
            p_list = _prefer_stdin_or_direct(by_cwe_patched[cwe])
            # 21 negative control patched testcases evaluated with Guided
            targets.append(("multi_cwe_patched", str(p_list[0]), False))
        elif len(v_list) > 1:
            targets.append(("multi_cwe_vuln", str(v_list[1]), False))

    # 4. Real-World Open-Source CVE stripped binaries (PrimeVul: 15 pre-patch vuln + 15 post-patch fixed = 30 binaries)
    # Both pre-patch and post-patch pairs are evaluated head-to-head (all 30 paired)
    pv_dir = Path(root_dir) / "data" / "primevul_binaries"
    pv_vuln = sorted(p for p in pv_dir.glob("*_VULN_O0.out") if not p.name.startswith("._"))
    seen_projs = defaultdict(int)
    chosen_pv = []
    for vp in pv_vuln:
        parts = vp.name.split("_")
        proj = parts[2] if len(parts) > 2 else "oss"
        fp = pv_dir / vp.name.replace("_VULN_O0.out", "_PATCHED_O0.out")
        if fp.exists() and seen_projs[proj] < 2:
            seen_projs[proj] += 1
            chosen_pv.append((vp, fp))
        if len(chosen_pv) >= 15:
            break
    for vp, fp in chosen_pv:
        targets.append(("primevul_cve_vuln", str(vp), True))
        targets.append(("primevul_cve_fixed", str(fp), True))

    # 5. Production macOS/BSD System Utilities (11 stripped system binaries -> all 11 paired)
    rw_dir = Path(root_dir) / "data" / "real_world_binaries"
    preferred_rw = [
        "real_bzip2.bin", "real_gzip.bin", "real_sed.bin", "real_patch.bin",
        "real_diff.bin", "real_hexdump.bin", "real_sort.bin", "real_uniq.bin",
        "real_tr.bin", "real_wc.bin", "real_cut.bin",
    ]
    for rname in preferred_rw:
        rp = rw_dir / rname
        if rp.exists():
            targets.append(("production_system", str(rp), True))

    return targets


def run_paired_bootstrap_analysis(paired_runs: list, n_boot: int = 1000, seed: int = 42) -> dict:
    rng = np.random.default_rng(seed)
    n = len(paired_runs)
    if n == 0:
        return {}

    boot_speedups = []
    boot_state_reds = []
    boot_step_reds = []
    boot_time_speedups = []

    for _ in range(n_boot):
        sample_idx = rng.integers(0, n, size=n)
        sample = [paired_runs[i] for i in sample_idx]

        sum_u_time = sum(s["unguided_time_s"] for s in sample)
        sum_g_time = sum(s["gnn_guided_time_s"] for s in sample)
        boot_speedups.append(sum_u_time / max(sum_g_time, 1e-4))

        sum_u_states = sum(s.get("unguided_states", 0) for s in sample)
        sum_g_states = sum(s.get("gnn_guided_states", 0) for s in sample)
        boot_state_reds.append((1.0 - (sum_g_states / max(sum_u_states, 1))) * 100.0)

        s_both_steps = [
            (s["unguided_steps_to_vuln"], s["gnn_guided_steps_to_vuln"])
            for s in sample
            if s.get("unguided_steps_to_vuln") is not None and s.get("gnn_guided_steps_to_vuln") is not None
        ]
        if s_both_steps:
            u_st_mean = np.mean([x[0] for x in s_both_steps])
            g_st_mean = np.mean([x[1] for x in s_both_steps])
            boot_step_reds.append(u_st_mean / max(g_st_mean, 1e-4))

        s_both_times = [
            (s["unguided_time_to_vuln_ms"], s["gnn_guided_time_to_vuln_ms"])
            for s in sample
            if s.get("unguided_time_to_vuln_ms") is not None and s.get("gnn_guided_time_to_vuln_ms") is not None
        ]
        if s_both_times:
            u_tm_mean = np.mean([x[0] for x in s_both_times])
            g_tm_mean = np.mean([x[1] for x in s_both_times])
            boot_time_speedups.append(u_tm_mean / max(g_tm_mean, 1e-4))

    return {
        "n_resamples": n_boot,
        "seed": seed,
        "speedup_x": {
            "mean": round(float(np.mean(boot_speedups)), 3),
            "ci_95": [round(float(np.percentile(boot_speedups, 2.5)), 3), round(float(np.percentile(boot_speedups, 97.5)), 3)],
        },
        "state_reduction_pct": {
            "mean": round(float(np.mean(boot_state_reds)), 2),
            "ci_95": [round(float(np.percentile(boot_state_reds, 2.5)), 2), round(float(np.percentile(boot_state_reds, 97.5)), 2)],
        },
        "steps_to_vuln_reduction_ratio": {
            "mean": round(float(np.mean(boot_step_reds)), 3) if boot_step_reds else None,
            "ci_95": [round(float(np.percentile(boot_step_reds, 2.5)), 3), round(float(np.percentile(boot_step_reds, 97.5)), 3)] if boot_step_reds else None,
        },
        "time_to_vuln_speedup_ratio": {
            "mean": round(float(np.mean(boot_time_speedups)), 3) if boot_time_speedups else None,
            "ci_95": [round(float(np.percentile(boot_time_speedups, 2.5)), 3), round(float(np.percentile(boot_time_speedups, 97.5)), 3)] if boot_time_speedups else None,
        },
    }


def run_benchmark(output_path: str = None):
    if output_path is None:
        output_path = os.path.join(root_dir, "benchmark_symbolic_results.json")

    print("=" * 80)
    print("NeuroZ3 — End-to-End Neuro-Symbolic & Z3 SMT Verification Benchmark (Phase 4)")
    print("=" * 80)

    model, temp, thresh = load_trained_gnn()
    print(f"[+] Loaded trained 40-dim VulnGNN (T={temp:.4f}, threshold={thresh:.4f})")

    targets = select_stratified_targets()
    paired_target_count = sum(1 for t in targets if t[2])
    print(f"[+] Selected {len(targets)} real stripped binaries across 5 benchmark strata ({paired_target_count} paired head-to-head)")

    results_by_group = defaultdict(list)
    flat_results = []

    for idx, (group, bpath, do_unguided) in enumerate(targets):
        bname = os.path.basename(bpath)
        paired_tag = "[PAIRED]" if do_unguided else "[GUIDED]"
        print(f"[{idx+1:03d}/{len(targets):03d}] {paired_tag} ({group:18s}) {bname[:38]:38s} ...", end=" ", flush=True)
        res = benchmark_single_binary(bpath, model, thresh, max_steps=90, compare_unguided=do_unguided)
        res["group"] = group
        flat_results.append(res)
        results_by_group[group].append(res)
        sp_str = f"| Speedup: {res['speedup_ratio']:.2f}x" if res["speedup_ratio"] is not None else ""
        st_str = f"| StRed: {res['state_reduction_pct']}%" if res.get("state_reduction_pct") is not None else ""
        print(
            f"[{res['status']}] G_Time={res['gnn_guided_time_s']:.2f}s (St={res['gnn_guided_states']}) "
            f"| Vulns={res['vuln_count']} | SAT={res['solver_sat_count']} "
            f"| LiveCrash={res['verified_live_crashes']} {sp_str} {st_str}",
            flush=True,
        )

    # 1. Global Metrics across all 90 binaries
    total_guided_time = sum(r["gnn_guided_time_s"] for r in flat_results)
    total_nodes = sum(r["cfg_nodes"] for r in flat_results)
    total_vulns = sum(r["vuln_count"] for r in flat_results)
    total_sat = sum(r["solver_sat_count"] for r in flat_results)
    success_count = sum(1 for r in flat_results if r["status"] == "SUCCESS")
    total_live_crashes = sum(r.get("verified_live_crashes", 0) for r in flat_results)

    all_guided_solver_counts = {"SAT": 0, "UNSAT": 0, "UNKNOWN": 0, "TIMEOUT": 0, "ERROR": 0}
    for r in flat_results:
        for k, v in r.get("gnn_guided_solver_counts", {}).items():
            all_guided_solver_counts[k] = all_guided_solver_counts.get(k, 0) + v

    all_solver_ms = [
        v["solver_time_ms"]
        for r in flat_results
        for v in r["vulnerabilities"]
        if v.get("solver_time_ms", 0.0) > 0
    ]

    # 2. Head-to-Head Paired Evaluation (N=69)
    paired_runs = [r for r in flat_results if r.get("unguided_time_s") is not None and r["status"] == "SUCCESS"]
    sum_guided_paired = sum(r["gnn_guided_time_s"] for r in paired_runs)
    sum_unguided_paired = sum(r["unguided_time_s"] for r in paired_runs)
    sum_guided_states = sum(r.get("gnn_guided_states", 0) for r in paired_runs)
    sum_unguided_states = sum(r.get("unguided_states", 0) for r in paired_runs)

    all_unguided_solver_counts = {"SAT": 0, "UNSAT": 0, "UNKNOWN": 0, "TIMEOUT": 0, "ERROR": 0}
    for r in paired_runs:
        for k, v in r.get("unguided_solver_counts", {}).items():
            all_unguided_solver_counts[k] = all_unguided_solver_counts.get(k, 0) + v

    speedup_list = [r["speedup_ratio"] for r in paired_runs if r.get("speedup_ratio") is not None]
    state_red_list = [r["state_reduction_pct"] for r in paired_runs if r.get("state_reduction_pct") is not None]

    guided_steps_list = [r["gnn_guided_steps_to_vuln"] for r in paired_runs if r.get("gnn_guided_steps_to_vuln") is not None]
    unguided_steps_list = [r["unguided_steps_to_vuln"] for r in paired_runs if r.get("unguided_steps_to_vuln") is not None]

    guided_time_vuln_list = [r["gnn_guided_time_to_vuln_ms"] for r in paired_runs if r.get("gnn_guided_time_to_vuln_ms") is not None]
    unguided_time_vuln_list = [r["unguided_time_to_vuln_ms"] for r in paired_runs if r.get("unguided_time_to_vuln_ms") is not None]

    both_found_steps = [
        (r["unguided_steps_to_vuln"], r["gnn_guided_steps_to_vuln"])
        for r in paired_runs
        if r.get("unguided_steps_to_vuln") is not None and r.get("gnn_guided_steps_to_vuln") is not None
    ]
    both_found_times = [
        (r["unguided_time_to_vuln_ms"], r["gnn_guided_time_to_vuln_ms"])
        for r in paired_runs
        if r.get("unguided_time_to_vuln_ms") is not None and r.get("gnn_guided_time_to_vuln_ms") is not None
    ]

    # 3. Paired 1,000x Bootstrap Confidence Intervals
    bootstrap_ci = run_paired_bootstrap_analysis(paired_runs, n_boot=1000, seed=42)

    summary = {
        "benchmark_metadata": {
            "phase": "Phase 4 Neuro-Symbolic Integration and Guided Symbolic Execution Benchmark",
            "date": time.strftime("%Y-%m-%d %H:%M:%S"),
            "total_binaries": len(flat_results),
            "paired_binaries": len(paired_runs),
            "guided_scheduler": "MaxHeap (H(s) = node_risk + gamma*reachable_risk - lambda*depth)",
            "unguided_scheduler": "Depth-First Search (DFS standard baseline)",
            "max_steps_budget": 90,
            "alarm_timeout_seconds": 15,
        },
        "global_results": {
            "total_binaries": len(flat_results),
            "successful_scans": success_count,
            "failed_scans": len(flat_results) - success_count,
            "total_gnn_guided_time_s": round(total_guided_time, 2),
            "avg_gnn_guided_time_per_binary_s": round(total_guided_time / max(len(flat_results), 1), 3),
            "total_cfg_nodes": total_nodes,
            "total_vulnerabilities_detected": total_vulns,
            "total_sat_proofs": total_sat,
            "total_verified_live_crashes": total_live_crashes,
            "mean_z3_solver_time_ms": round(float(np.mean(all_solver_ms)), 3) if all_solver_ms else 0.0,
            "median_z3_solver_time_ms": round(float(np.median(all_solver_ms)), 3) if all_solver_ms else 0.0,
            "all_binaries_guided_solver_counts": all_guided_solver_counts,
        },
        "paired_head_to_head": {
            "paired_binary_count": len(paired_runs),
            "paired_unguided_total_time_s": round(sum_unguided_paired, 2),
            "paired_gnn_guided_total_time_s": round(sum_guided_paired, 2),
            "overall_symbolic_speedup_x": round(sum_unguided_paired / max(sum_guided_paired, 1e-4), 2),
            "speedup_95_ci": bootstrap_ci.get("speedup_x", {}).get("ci_95"),
            "paired_unguided_total_states": sum_unguided_states,
            "paired_gnn_guided_total_states": sum_guided_states,
            "overall_state_reduction_pct": round((1.0 - (sum_guided_states / max(sum_unguided_states, 1))) * 100, 2),
            "overall_state_reduction_ratio": round(sum_unguided_states / max(sum_guided_states, 1), 2),
            "state_reduction_pct_95_ci": bootstrap_ci.get("state_reduction_pct", {}).get("ci_95"),
            "mean_speedup_per_binary": round(float(np.mean(speedup_list)), 2) if speedup_list else 0.0,
            "median_speedup_per_binary": round(float(np.median(speedup_list)), 2) if speedup_list else 0.0,
            "mean_state_reduction_pct_per_binary": round(float(np.mean(state_red_list)), 2) if state_red_list else 0.0,
            "median_state_reduction_pct_per_binary": round(float(np.median(state_red_list)), 2) if state_red_list else 0.0,
            "steps_to_first_vuln": {
                "guided_mean": round(float(np.mean(guided_steps_list)), 2) if guided_steps_list else None,
                "guided_median": round(float(np.median(guided_steps_list)), 2) if guided_steps_list else None,
                "unguided_mean": round(float(np.mean(unguided_steps_list)), 2) if unguided_steps_list else None,
                "unguided_median": round(float(np.median(unguided_steps_list)), 2) if unguided_steps_list else None,
                "paired_steps_reduction_ratio_mean": round(float(np.mean([u / max(g, 1) for u, g in both_found_steps])), 2) if both_found_steps else None,
                "paired_steps_reduction_95_ci": bootstrap_ci.get("steps_to_vuln_reduction_ratio", {}).get("ci_95"),
            },
            "time_to_first_vuln_ms": {
                "guided_mean": round(float(np.mean(guided_time_vuln_list)), 2) if guided_time_vuln_list else None,
                "guided_median": round(float(np.median(guided_time_vuln_list)), 2) if guided_time_vuln_list else None,
                "unguided_mean": round(float(np.mean(unguided_time_vuln_list)), 2) if unguided_time_vuln_list else None,
                "unguided_median": round(float(np.median(unguided_time_vuln_list)), 2) if unguided_time_vuln_list else None,
                "paired_time_speedup_mean": round(float(np.mean([u / max(g, 1e-4) for u, g in both_found_times])), 2) if both_found_times else None,
                "paired_time_speedup_95_ci": bootstrap_ci.get("time_to_vuln_speedup_ratio", {}).get("ci_95"),
            },
            "timeouts": {
                "unguided_timeout_count": sum(1 for r in paired_runs if r.get("unguided_timed_out")),
                "guided_timeout_count": sum(1 for r in paired_runs if r.get("gnn_guided_timed_out")),
            },
            "frontier_size": {
                "guided_max_frontier_mean": round(float(np.mean([r.get("gnn_guided_max_frontier", 0) for r in paired_runs])), 2),
                "unguided_max_frontier_mean": round(float(np.mean([r.get("unguided_max_frontier", 0) for r in paired_runs])), 2),
            },
            "solver_status_comparison": {
                "guided": {
                    k: sum(r.get("gnn_guided_solver_counts", {}).get(k, 0) for r in paired_runs)
                    for k in ["SAT", "UNSAT", "UNKNOWN", "TIMEOUT", "ERROR"]
                },
                "unguided": all_unguided_solver_counts,
            },
            "bootstrap_analysis": bootstrap_ci,
        },
        "by_group": {
            g: {
                "count": len(items),
                "paired_count": sum(1 for i in items if i.get("unguided_time_s") is not None),
                "total_nodes": sum(i["cfg_nodes"] for i in items),
                "total_vulns": sum(i["vuln_count"] for i in items),
                "binaries_with_vuln": sum(1 for i in items if i["vuln_count"] > 0),
                "total_sat": sum(i["solver_sat_count"] for i in items),
                "verified_live_crashes": sum(i.get("verified_live_crashes", 0) for i in items),
                "avg_guided_time_s": round(sum(i["gnn_guided_time_s"] for i in items) / max(len(items), 1), 3),
                "avg_unguided_time_s": round(
                    sum(i["unguided_time_s"] for i in items if i["unguided_time_s"] is not None)
                    / max(sum(1 for i in items if i["unguided_time_s"] is not None), 1),
                    3,
                ) if any(i.get("unguided_time_s") is not None for i in items) else None,
                "overall_group_speedup_x": round(
                    sum(i["unguided_time_s"] for i in items if i["unguided_time_s"] is not None)
                    / max(sum(i["gnn_guided_time_s"] for i in items if i["unguided_time_s"] is not None), 1e-4),
                    2,
                ) if any(i.get("unguided_time_s") is not None for i in items) else None,
                "total_guided_states": sum(i.get("gnn_guided_states", 0) for i in items),
                "total_unguided_states": sum(i.get("unguided_states", 0) for i in items if i.get("unguided_states") is not None)
                if any(i.get("unguided_states") is not None for i in items) else None,
                "group_state_reduction_pct": round(
                    (1.0 - (sum(i.get("gnn_guided_states", 0) for i in items if i.get("unguided_states") is not None)
                            / max(sum(i.get("unguided_states", 0) for i in items if i.get("unguided_states") is not None), 1))) * 100,
                    2,
                ) if any(i.get("unguided_states") is not None for i in items) else None,
            }
            for g, items in results_by_group.items()
        },
    }

    final_payload = {"summary": summary, "binaries": flat_results}
    with open(output_path, "w") as f:
        json.dump(final_payload, f, indent=2)

    print("\n" + "=" * 80)
    print("PHASE 4: SYMBOLIC & NEURO-SYMBOLIC BENCHMARK SUMMARY")
    print("=" * 80)
    print(f"Total Real Binaries Scanned:    {summary['global_results']['total_binaries']} ({summary['global_results']['successful_scans']} SUCCESS)")
    print(f"Total CFG Basic Blocks:         {summary['global_results']['total_cfg_nodes']}")
    print(f"Total Vulnerabilities Detected: {summary['global_results']['total_vulnerabilities_detected']} ({summary['global_results']['total_sat_proofs']} Z3 SAT proofs)")
    print(f"Total Verified Live Crashes:    {summary['global_results']['total_verified_live_crashes']}")
    print(f"Mean Z3 SMT Solver Latency:     {summary['global_results']['mean_z3_solver_time_ms']} ms (median {summary['global_results']['median_z3_solver_time_ms']} ms)")
    print("-" * 80)
    p_info = summary["paired_head_to_head"]
    print(f"Head-to-Head Comparison ({p_info['paired_binary_count']} Binaries):")
    print(f"  Wall-Clock Time:   Unguided {p_info['paired_unguided_total_time_s']}s vs Guided {p_info['paired_gnn_guided_total_time_s']}s")
    print(f"  Speedup Ratio:     {p_info['overall_symbolic_speedup_x']}x (95% CI: [{p_info['speedup_95_ci'][0]}, {p_info['speedup_95_ci'][1]}])")
    print(f"  States Explored:   Unguided {p_info['paired_unguided_total_states']} vs Guided {p_info['paired_gnn_guided_total_states']}")
    print(f"  State Reduction:   {p_info['overall_state_reduction_pct']}% (95% CI: [{p_info['state_reduction_pct_95_ci'][0]}%, {p_info['state_reduction_pct_95_ci'][1]}%])")
    print(f"  15s Timeouts:      Unguided {p_info['timeouts']['unguided_timeout_count']} vs Guided {p_info['timeouts']['guided_timeout_count']}")
    print(f"  Guided Solver:     {p_info['solver_status_comparison']['guided']}")
    print(f"  Unguided Solver:   {p_info['solver_status_comparison']['unguided']}")
    print(f"[+] Complete results written -> {output_path}")


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root_dir, "benchmark_symbolic_results.json")
    run_benchmark(out_file)
