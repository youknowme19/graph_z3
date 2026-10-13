#!/usr/bin/env python3
"""
Comprehensive Binary Analysis & Symbolic Verification Benchmark Runner
========================================================================
Benchmarks AnalysisBackendProvider, angr CFG recovery, symbolic execution,
Z3 constraint solving, and exploit primitive classification across all binaries.
"""

import os
import sys
import time
import json
import hashlib
from pathlib import Path

# Add project root and src to path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from src.core.interfaces import AnalysisBackendProvider

def get_file_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def benchmark_single_binary(binary_path: str, max_steps: int = 150) -> dict:
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
        "analysis_time_s": 0.0,
        "trace_steps": 0,
        "vulnerabilities": [],
        "vuln_count": 0,
        "vuln_types": [],
        "solver_sat_count": 0,
        "avg_solver_time_ms": 0.0,
        "peak_cvss": 0.0,
        "composite_risk_score": 0.0,
        "mitigations": [],
        "exploit_primitives": []
    }

    t0 = time.time()
    try:
        backend = AnalysisBackendProvider(binary_path, max_steps=max_steps)
        
        # CFG stats
        try:
            cfg = backend.engine.loader.get_cfg()
            if cfg is not None:
                result["cfg_nodes"] = len(cfg.graph.nodes())
                result["cfg_edges"] = len(cfg.graph.edges())
            funcs = backend.engine.loader.get_functions()
            if funcs is not None:
                result["num_functions"] = len(funcs)
        except Exception as e:
            pass

        # Scan vulnerabilities
        vulns = backend.scan_vulnerabilities()
        t1 = time.time()
        result["analysis_time_s"] = round(t1 - t0, 3)
        result["vuln_count"] = len(vulns)
        result["vuln_types"] = list(set(v.get("vuln_type") for v in vulns))

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
            if v.get("solver_time_ms") is not None:
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
        result["composite_risk_score"] = round(0.7 * (max(cvss_scores) if cvss_scores else 0.0) + 0.3 * (sum(cvss_scores)/len(cvss_scores) if cvss_scores else 0.0), 2)
        result["exploit_primitives"] = list(set(primitives))
        result["mitigations"] = list(all_mitigations)

    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        result["analysis_time_s"] = round(time.time() - t0, 3)

    return result

def run_benchmark(output_path: str = "benchmark_symbolic_results.json"):
    print("=" * 70)
    print("Neuro-Symbolic Fuzzer — Full Binary Benchmark Suite")
    print("=" * 70)

    all_targets = []

    # 1. Samples
    samples_dir = os.path.join(root_dir, "data", "samples")
    if os.path.exists(samples_dir):
        for p in sorted(Path(samples_dir).glob("*.bin")):
            if not p.name.startswith("._"):
                all_targets.append(("samples", str(p)))

    # 2. Train binaries (Juliet ELF)
    train_dir = os.path.join(root_dir, "data", "train_binaries")
    if os.path.exists(train_dir):
        for p in sorted(Path(train_dir).glob("*.out")):
            if not p.name.startswith("._"):
                all_targets.append(("juliet_train", str(p)))

    # 3. Benchmark suite binary
    bench_bin = os.path.join(root_dir, "tests", "test_benchmarks_binary")
    if os.path.exists(bench_bin) and not os.path.basename(bench_bin).startswith("._"):
        all_targets.append(("test_suite", bench_bin))

    print(f"[+] Total binaries queued for benchmark: {len(all_targets)}")
    results_by_group = {"samples": [], "juliet_train": [], "test_suite": []}
    flat_results = []

    for idx, (group, bpath) in enumerate(all_targets):
        bname = os.path.basename(bpath)
        print(f"[{idx+1}/{len(all_targets)}] Benchmarking ({group}): {bname} ...", end=" ", flush=True)
        res = benchmark_single_binary(bpath, max_steps=120)
        res["group"] = group
        flat_results.append(res)
        results_by_group[group].append(res)
        print(f"[{res['status']}] {res['analysis_time_s']}s | Nodes: {res['cfg_nodes']} | Vulns: {res['vuln_count']} | SAT: {res['solver_sat_count']} | Peak CVSS: {res['peak_cvss']}")

    # Aggregated Summary
    total_time = sum(r["analysis_time_s"] for r in flat_results)
    total_nodes = sum(r["cfg_nodes"] for r in flat_results)
    total_vulns = sum(r["vuln_count"] for r in flat_results)
    total_sat = sum(r["solver_sat_count"] for r in flat_results)
    success_count = sum(1 for r in flat_results if r["status"] == "SUCCESS")

    summary = {
        "total_binaries": len(flat_results),
        "successful_scans": success_count,
        "failed_scans": len(flat_results) - success_count,
        "total_analysis_time_s": round(total_time, 2),
        "avg_analysis_time_per_binary_s": round(total_time / len(flat_results), 3) if flat_results else 0.0,
        "total_cfg_nodes": total_nodes,
        "total_vulnerabilities_detected": total_vulns,
        "total_sat_proofs": total_sat,
        "by_group": {
            g: {
                "count": len(items),
                "total_vulns": sum(i["vuln_count"] for i in items),
                "total_sat": sum(i["solver_sat_count"] for i in items),
                "avg_time_s": round(sum(i["analysis_time_s"] for i in items)/len(items), 3) if items else 0.0
            } for g, items in results_by_group.items()
        }
    }

    final_payload = {
        "summary": summary,
        "binaries": flat_results
    }

    with open(output_path, "w") as f:
        json.dump(final_payload, f, indent=2)

    print("\n" + "=" * 70)
    print("BENCHMARK SUMMARY")
    print("=" * 70)
    print(f"Total Binaries Scanned: {summary['total_binaries']}")
    print(f"Successful Scans:       {summary['successful_scans']}")
    print(f"Total Analysis Time:    {summary['total_analysis_time_s']}s (avg {summary['avg_analysis_time_per_binary_s']}s/bin)")
    print(f"Total CFG Nodes:        {summary['total_cfg_nodes']}")
    print(f"Total Vulns Detected:   {summary['total_vulnerabilities_detected']}")
    print(f"Total SAT Z3 Proofs:    {summary['total_sat_proofs']}")
    print(f"[+] Output written to:  {output_path}")

if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "benchmark_symbolic_results.json"
    run_benchmark(out_file)
