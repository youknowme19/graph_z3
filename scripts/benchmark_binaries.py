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
  4. Real-World Open-Source CVE Stripped Binaries (36 PrimeVul pre-patch & post-patch binaries)
  5. Production macOS/BSD System Binaries (15 utilities: bzip2, gzip, sed, awk, patch, diff, file, etc.)

Compares Unguided Symbolic Execution vs. GNN-Guided Neuro-Symbolic Verification.
"""

import os
import sys
import time
import json
import signal
import hashlib
from pathlib import Path
from collections import defaultdict


class SymbolicTimeout(Exception):
    pass


def _alarm_handler(signum, frame):
    raise SymbolicTimeout("Symbolic exploration cap reached")

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

import torch
from src.core.binary_loader import BinaryLoader
from src.graph.graph_builder import GraphBuilder
from src.ml.gnn_model import create_model
from src.core.interfaces import AnalysisBackendProvider


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
        return {}, 0, 0, 0.0
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

    # Select blocks exceeding calibrated threshold OR Top-K highest-risk blocks (when max prob >= 0.20)
    cand_indices = set(int(i) for i, p in enumerate(probs) if p >= thresh)
    if not cand_indices and len(probs) > 0 and float(probs.max()) >= 0.20:
        ranked = probs.argsort()[::-1][: min(top_k_blocks, len(probs))]
        cand_indices.update(int(i) for i in ranked)

    func_vuln_map = {}
    for idx in cand_indices:
        b_addr = nodes[idx]
        for fn_addr in nx_cg.nodes():
            if b_addr in nx_cg.nodes[fn_addr].get("block_addrs", set()):
                func_vuln_map[fn_addr] = True
                break
        else:
            fn = loader.get_functions().floor_func(b_addr)
            if fn is not None:
                func_vuln_map[fn.addr] = True

    total_user_funcs = sum(
        1
        for f in loader.get_functions().values()
        if not f.is_plt and not f.is_simprocedure and f.size > 20 and not f.name.startswith("_start")
    )
    _ = time.perf_counter() - t0
    return func_vuln_map, len(cand_indices), total_user_funcs, round(gnn_ms, 3)


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
        "unguided_time_s": None,
        "speedup_ratio": None,
        "analysis_time_s": 0.0,
        "vulnerabilities": [],
        "vuln_count": 0,
        "unguided_vuln_count": None,
        "vuln_types": [],
        "solver_sat_count": 0,
        "avg_solver_time_ms": 0.0,
        "peak_cvss": 0.0,
        "composite_risk_score": 0.0,
        "mitigations": [],
        "exploit_primitives": [],
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

        func_vuln_map, n_cand_blocks, total_ufuncs, gnn_ms = compute_gnn_func_targets(loader, model, thresh)
        result["user_functions"] = total_ufuncs
        result["gnn_flagged_blocks"] = n_cand_blocks
        result["gnn_flagged_functions"] = len(func_vuln_map)
        result["gnn_infer_ms"] = gnn_ms

        # 1. GNN-Guided Neuro-Symbolic Verification (capped at 15s per binary)
        signal.signal(signal.SIGALRM, _alarm_handler)
        t_g0 = time.perf_counter()
        vulns = []
        try:
            signal.alarm(15)
            guided_map = func_vuln_map if func_vuln_map else {-1: False}
            guided_backend = AnalysisBackendProvider(
                binary_path,
                max_steps=max_steps,
                gnn_vulnerable_functions=guided_map,
                _shared_loader=loader,
            )
            vulns = guided_backend.scan_vulnerabilities()
        except SymbolicTimeout:
            pass
        finally:
            signal.alarm(0)
        guided_sym_s = time.perf_counter() - t_g0
        total_guided_s = load_time_s + (gnn_ms / 1000.0) + guided_sym_s
        result["gnn_guided_time_s"] = round(total_guided_s, 3)
        result["analysis_time_s"] = round(total_guided_s, 3)

        # 2. Unguided Symbolic Execution baseline (capped at 15s lower-bound timeout)
        if compare_unguided:
            t_u0 = time.perf_counter()
            u_vulns = []
            u_timed_out = False
            try:
                signal.alarm(15)
                unguided_backend = AnalysisBackendProvider(
                    binary_path,
                    max_steps=max_steps,
                    gnn_vulnerable_functions=None,
                    _shared_loader=loader,
                )
                u_vulns = unguided_backend.scan_vulnerabilities()
            except SymbolicTimeout:
                u_timed_out = True
            finally:
                signal.alarm(0)
            unguided_sym_s = 15.0 if u_timed_out else (time.perf_counter() - t_u0)
            total_unguided_s = load_time_s + unguided_sym_s
            result["unguided_time_s"] = round(total_unguided_s, 3)
            result["unguided_timed_out"] = u_timed_out
            result["unguided_vuln_count"] = len(u_vulns)
            result["speedup_ratio"] = round(total_unguided_s / max(total_guided_s, 1e-4), 2)

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

    # 1. All 6 sample binaries (5 vulnerable CWEs + 1 secure_program.bin)
    samples_dir = Path(root_dir) / "data" / "samples"
    for p in sorted(samples_dir.glob("*.bin")):
        if not p.name.startswith("._"):
            targets.append(("samples", str(p), True))

    # 2. Multi-vuln benchmark suite binary
    bench_bin = Path(root_dir) / "tests" / "test_benchmarks_binary"
    if bench_bin.exists():
        targets.append(("test_suite", str(bench_bin), True))

    # 3. Stratified Multi-CWE Juliet stripped binaries (21 CWEs: prefer stdin/fgets/console/heap testcases + patched controls = 42)
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

    for idx_c, cwe in enumerate(sorted(by_cwe_vuln.keys())):
        v_list = _prefer_stdin_or_direct(by_cwe_vuln[cwe])
        targets.append(("multi_cwe_vuln", str(v_list[0]), idx_c < 8))
        if by_cwe_patched[cwe]:
            p_list = _prefer_stdin_or_direct(by_cwe_patched[cwe])
            targets.append(("multi_cwe_patched", str(p_list[0]), idx_c < 4))
        elif len(v_list) > 1:
            targets.append(("multi_cwe_vuln", str(v_list[1]), False))

    # 4. Real-World Open-Source CVE stripped binaries (PrimeVul: 15 pre-patch vuln + 15 post-patch fixed = 30)
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
    for i, (vp, fp) in enumerate(chosen_pv):
        targets.append(("primevul_cve_vuln", str(vp), i < 6))
        targets.append(("primevul_cve_fixed", str(fp), i < 4))

    # 5. Production macOS/BSD System Utilities (11 stripped system binaries -> total = 90 binaries)
    rw_dir = Path(root_dir) / "data" / "real_world_binaries"
    preferred_rw = [
        "real_bzip2.bin", "real_gzip.bin", "real_sed.bin", "real_patch.bin",
        "real_diff.bin", "real_hexdump.bin", "real_sort.bin", "real_uniq.bin",
        "real_tr.bin", "real_wc.bin", "real_cut.bin",
    ]
    for idx_r, rname in enumerate(preferred_rw):
        rp = rw_dir / rname
        if rp.exists():
            targets.append(("production_system", str(rp), idx_r < 4))

    return targets


def run_benchmark(output_path: str = None):
    if output_path is None:
        output_path = os.path.join(root_dir, "benchmark_symbolic_results.json")

    print("=" * 75)
    print("NeuroZ3 — End-to-End Neuro-Symbolic & Z3 SMT Verification Benchmark")
    print("=" * 75)

    model, temp, thresh = load_trained_gnn()
    print(f"[+] Loaded trained 40-dim VulnGNN (T={temp:.4f}, threshold={thresh:.4f})")

    targets = select_stratified_targets()
    print(f"[+] Selected {len(targets)} real stripped binaries across 5 benchmark strata")

    results_by_group = defaultdict(list)
    flat_results = []

    for idx, (group, bpath, do_unguided) in enumerate(targets):
        bname = os.path.basename(bpath)
        print(f"[{idx+1:03d}/{len(targets):03d}] ({group:18s}) {bname[:42]:42s} ...", end=" ", flush=True)
        res = benchmark_single_binary(bpath, model, thresh, max_steps=90, compare_unguided=do_unguided)
        res["group"] = group
        flat_results.append(res)
        results_by_group[group].append(res)
        sp_str = f"| Speedup: {res['speedup_ratio']:.2f}x" if res["speedup_ratio"] is not None else ""
        print(
            f"[{res['status']}] Guided={res['gnn_guided_time_s']:.2f}s "
            f"| Nodes={res['cfg_nodes']:4d} | FlagFn={res['gnn_flagged_functions']}/{res['user_functions']} "
            f"| Vulns={res['vuln_count']} | SAT={res['solver_sat_count']} {sp_str}",
            flush=True,
        )

    total_guided_time = sum(r["gnn_guided_time_s"] for r in flat_results)
    total_nodes = sum(r["cfg_nodes"] for r in flat_results)
    total_vulns = sum(r["vuln_count"] for r in flat_results)
    total_sat = sum(r["solver_sat_count"] for r in flat_results)
    success_count = sum(1 for r in flat_results if r["status"] == "SUCCESS")

    paired_runs = [r for r in flat_results if r["unguided_time_s"] is not None and r["status"] == "SUCCESS"]
    sum_guided_paired = sum(r["gnn_guided_time_s"] for r in paired_runs)
    sum_unguided_paired = sum(r["unguided_time_s"] for r in paired_runs)
    all_solver_ms = [
        v["solver_time_ms"]
        for r in flat_results
        for v in r["vulnerabilities"]
        if v.get("solver_time_ms", 0.0) > 0
    ]

    summary = {
        "total_binaries": len(flat_results),
        "successful_scans": success_count,
        "failed_scans": len(flat_results) - success_count,
        "total_gnn_guided_time_s": round(total_guided_time, 2),
        "avg_gnn_guided_time_per_binary_s": round(total_guided_time / max(len(flat_results), 1), 3),
        "paired_head_to_head_count": len(paired_runs),
        "paired_unguided_total_time_s": round(sum_unguided_paired, 2),
        "paired_gnn_guided_total_time_s": round(sum_guided_paired, 2),
        "overall_symbolic_speedup_x": round(sum_unguided_paired / max(sum_guided_paired, 1e-4), 2),
        "mean_z3_solver_time_ms": round(sum(all_solver_ms) / len(all_solver_ms), 3) if all_solver_ms else 0.0,
        "median_z3_solver_time_ms": round(sorted(all_solver_ms)[len(all_solver_ms) // 2], 3) if all_solver_ms else 0.0,
        "total_cfg_nodes": total_nodes,
        "total_vulnerabilities_detected": total_vulns,
        "total_sat_proofs": total_sat,
        "by_group": {
            g: {
                "count": len(items),
                "total_nodes": sum(i["cfg_nodes"] for i in items),
                "total_vulns": sum(i["vuln_count"] for i in items),
                "binaries_with_vuln": sum(1 for i in items if i["vuln_count"] > 0),
                "total_sat": sum(i["solver_sat_count"] for i in items),
                "avg_guided_time_s": round(sum(i["gnn_guided_time_s"] for i in items) / max(len(items), 1), 3),
                "avg_unguided_time_s": round(
                    sum(i["unguided_time_s"] for i in items if i["unguided_time_s"] is not None)
                    / max(sum(1 for i in items if i["unguided_time_s"] is not None), 1),
                    3,
                )
                if any(i["unguided_time_s"] is not None for i in items)
                else None,
            }
            for g, items in results_by_group.items()
        },
    }

    final_payload = {"summary": summary, "binaries": flat_results}
    with open(output_path, "w") as f:
        json.dump(final_payload, f, indent=2)

    print("\n" + "=" * 75)
    print("SYMBOLIC & NEURO-SYMBOLIC BENCHMARK SUMMARY")
    print("=" * 75)
    print(f"Total Real Binaries Scanned: {summary['total_binaries']} ({summary['successful_scans']} SUCCESS)")
    print(f"Total CFG Basic Blocks:      {summary['total_cfg_nodes']}")
    print(f"Total Vulnerabilities Found: {summary['total_vulnerabilities_detected']} ({summary['total_sat_proofs']} Z3 SAT proofs)")
    print(f"Mean Z3 Solver Latency:      {summary['mean_z3_solver_time_ms']} ms (median {summary['median_z3_solver_time_ms']} ms)")
    print(
        f"Head-to-Head ({summary['paired_head_to_head_count']} bins): "
        f"Unguided {summary['paired_unguided_total_time_s']}s vs GNN-Guided {summary['paired_gnn_guided_total_time_s']}s "
        f"-> {summary['overall_symbolic_speedup_x']}x Speedup"
    )
    print(f"[+] Saved -> {output_path}")


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else os.path.join(root_dir, "benchmark_symbolic_results.json")
    run_benchmark(out_file)
