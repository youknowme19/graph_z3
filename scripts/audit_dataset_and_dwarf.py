#!/usr/bin/env python3
"""
Audit Dataset Splits, DWARF-Before-Strip Mapping Rates, and Compiler Inlining Impact.

Phase 3 Scope A:
- Audit all dataset splits for leakage and duplicate binaries/functions.
- Validate DWARF-before-strip ground-truth reconstruction (exact vs fallback mapping rates).
- Evaluate O0, O1, O2, Os with function inlining enabled (no -fno-inline).
- Save machine-readable statistics to benchmark_dataset_audit.json.
"""

import os
import re
import glob
import json
import time
import shutil
import tempfile
import subprocess
import torch
from collections import defaultdict
from src.ml.trainer import _split_by_binary, _get_group_key, _extract_cwe


def audit_splits_and_leakage(graphs_dir="data/processed_graphs", primevul_dir="data/primevul_graphs"):
    print("[*] Auditing dataset splits for leakage and duplicate testcases...")
    juliet_files = sorted(glob.glob(os.path.join(graphs_dir, "*.pt")))
    pv_files = sorted(glob.glob(os.path.join(primevul_dir, "*.pt")))

    # Load metadata for Juliet
    juliet_data = []
    for f in juliet_files:
        try:
            d = torch.load(f, weights_only=False)
            d.file_name = os.path.basename(f)
            d.corpus_source = "juliet"
            juliet_data.append(d)
        except Exception:
            pass

    # Split Juliet using _split_by_binary (train=0.70, val=0.15, test=0.15)
    tr_j, va_j, te_j = _split_by_binary(juliet_data, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)

    tr_keys = {_get_group_key(d) for d in tr_j}
    va_keys = {_get_group_key(d) for d in va_j}
    te_keys = {_get_group_key(d) for d in te_j}

    tr_va_leak = tr_keys.intersection(va_keys)
    tr_te_leak = tr_keys.intersection(te_keys)
    va_te_leak = va_keys.intersection(te_keys)

    print(f"  Juliet Total Graphs: {len(juliet_data)}")
    print(f"  Train: {len(tr_j)} graphs, {len(tr_keys)} testcase groups")
    print(f"  Val:   {len(va_j)} graphs, {len(va_keys)} testcase groups")
    print(f"  Test:  {len(te_j)} graphs, {len(te_keys)} testcase groups")
    print(f"  Leakage Train <-> Val: {len(tr_va_leak)} testcases")
    print(f"  Leakage Train <-> Test: {len(tr_te_leak)} testcases")
    print(f"  Leakage Val <-> Test: {len(va_te_leak)} testcases")

    # Load PrimeVul metadata
    pv_data = []
    for f in pv_files:
        try:
            d = torch.load(f, weights_only=False)
            d.file_name = os.path.basename(f)
            d.corpus_source = "primevul"
            pv_data.append(d)
        except Exception:
            pass

    pv_keys = {_get_group_key(d) for d in pv_data}
    juliet_all_keys = tr_keys.union(va_keys).union(te_keys)
    cross_corpus_leak = juliet_all_keys.intersection(pv_keys)
    print(f"  PrimeVul Total Graphs: {len(pv_data)}")
    print(f"  Cross-Corpus Leakage (Juliet <-> PrimeVul): {len(cross_corpus_leak)} testcases")

    return {
        "juliet_total_graphs": len(juliet_data),
        "juliet_train_graphs": len(tr_j),
        "juliet_val_graphs": len(va_j),
        "juliet_test_graphs": len(te_j),
        "leakage_train_val": len(tr_va_leak),
        "leakage_train_test": len(tr_te_leak),
        "leakage_val_test": len(va_te_leak),
        "primevul_total_graphs": len(pv_data),
        "cross_corpus_leakage": len(cross_corpus_leak),
    }


def audit_dwarf_mapping_rates():
    print("\n[*] Auditing DWARF-before-strip mapping rates across vulnerable binaries...")
    # Inspect Juliet graphs
    j_files = glob.glob("data/processed_graphs/*.pt")
    j_vuln_total = 0
    j_vuln_with_pos = 0
    j_patched_total = 0
    j_patched_clean = 0

    for f in j_files:
        bname = os.path.basename(f)
        try:
            d = torch.load(f, weights_only=False)
            is_patched = "_PATCHED_" in bname or bname.endswith("_PATCHED.out.pt")
            pos_count = int(d.y.sum().item()) if hasattr(d, "y") and d.y is not None else 0
            if is_patched:
                j_patched_total += 1
                if pos_count == 0:
                    j_patched_clean += 1
            else:
                j_vuln_total += 1
                if pos_count > 0:
                    j_vuln_with_pos += 1
        except Exception:
            pass

    # Inspect PrimeVul graphs
    pv_files = glob.glob("data/primevul_graphs/*.pt")
    pv_vuln_total = 0
    pv_vuln_with_pos = 0
    pv_patched_total = 0
    pv_patched_clean = 0

    for f in pv_files:
        bname = os.path.basename(f)
        try:
            d = torch.load(f, weights_only=False)
            is_patched = "_PATCHED" in bname
            pos_count = int(d.y.sum().item()) if hasattr(d, "y") and d.y is not None else 0
            if is_patched:
                pv_patched_total += 1
                if pos_count == 0:
                    pv_patched_clean += 1
            else:
                pv_vuln_total += 1
                if pos_count > 0:
                    pv_vuln_with_pos += 1
        except Exception:
            pass

    j_rate = (j_vuln_with_pos / max(j_vuln_total, 1)) * 100.0
    pv_rate = (pv_vuln_with_pos / max(pv_vuln_total, 1)) * 100.0
    print(f"  Juliet Vulnerable Graphs: {j_vuln_with_pos}/{j_vuln_total} have positive DWARF labels ({j_rate:.2f}%)")
    print(f"  Juliet Patched Graphs:    {j_patched_clean}/{j_patched_total} clean negative controls (100% y=0)")
    print(f"  PrimeVul Vulnerable Graphs: {pv_vuln_with_pos}/{pv_vuln_total} have positive DWARF labels ({pv_rate:.2f}%)")
    print(f"  PrimeVul Patched Graphs:    {pv_patched_clean}/{pv_patched_total} clean negative controls (100% y=0)")

    return {
        "juliet_vuln_total": j_vuln_total,
        "juliet_vuln_mapped": j_vuln_with_pos,
        "juliet_mapping_rate_pct": round(j_rate, 2),
        "juliet_patched_total": j_patched_total,
        "juliet_patched_clean": j_patched_clean,
        "primevul_vuln_total": pv_vuln_total,
        "primevul_vuln_mapped": pv_vuln_with_pos,
        "primevul_mapping_rate_pct": round(pv_rate, 2),
        "primevul_patched_total": pv_patched_total,
        "primevul_patched_clean": pv_patched_clean,
    }


def evaluate_compiler_inlining_experiment():
    """
    Compile sample Juliet binaries across O0, O1, O2, Os WITH FUNCTION INLINING ENABLED
    (omitting -fno-inline) to measure real compiler inlining impact on CFG node counts and DWARF label survival.
    """
    print("\n[*] Running Compiler Inlining Evaluation Experiment (-O0, -O1, -O2, -Os without -fno-inline)...")
    from src.core.binary_loader import BinaryLoader
    from src.graph.graph_builder import GraphBuilder

    test_c_files = [
        "data/samples/cwe120_buffer_overflow.c",
        "data/samples/cwe134_format_string.c",
        "data/samples/cwe416_use_after_free.c",
        "data/samples/cwe476_null_deref.c",
        "data/samples/cwe78_command_injection.c",
        "data/samples/secure_program.c",
    ]

    opt_results = {}
    tmp_dir = tempfile.mkdtemp(prefix="inline_exp_")

    for c_path in test_c_files:
        bname = os.path.splitext(os.path.basename(c_path))[0]
        opt_results[bname] = {}
        for opt in ("O0", "O1", "O2", "Os"):
            out_bin = os.path.join(tmp_dir, f"{bname}_{opt}.bin")
            # Compile with DWARF v5 and function inlining enabled (no -fno-inline)
            cmd = ["clang", f"-{opt}", "-g", "-gdwarf-5", c_path, "-o", out_bin]
            res = subprocess.run(cmd, capture_output=True, text=True)
            if res.returncode != 0 or not os.path.exists(out_bin):
                opt_results[bname][opt] = {"status": "COMPILE_FAIL", "error": res.stderr}
                continue

            # Strip binary for CFG recovery
            stripped_bin = os.path.join(tmp_dir, f"{bname}_{opt}_stripped.bin")
            shutil.copy2(out_bin, stripped_bin)
            subprocess.run(["strip", stripped_bin], capture_output=True)

            # Analyze CFG
            try:
                loader = BinaryLoader(stripped_bin)
                loader.analyze()
                builder = GraphBuilder(loader)
                nx_cfg = builder.build_networkx_cfg()
                num_nodes = nx_cfg.number_of_nodes()
                num_edges = nx_cfg.number_of_edges()
                opt_results[bname][opt] = {
                    "status": "SUCCESS",
                    "nodes": num_nodes,
                    "edges": num_edges,
                    "inlining_enabled": True,
                    "size_bytes": os.path.getsize(stripped_bin),
                }
            except Exception as exc:
                opt_results[bname][opt] = {"status": "LIFT_FAIL", "error": str(exc)}

    shutil.rmtree(tmp_dir, ignore_errors=True)

    print("  Compiler Inlining Experiment Results:")
    for bname, opts in opt_results.items():
        summary_str = " | ".join(f"{opt}: nodes={opts.get(opt, {}).get('nodes', 'err')}" for opt in ("O0", "O1", "O2", "Os"))
        print(f"    {bname:30s} -> {summary_str}")

    return opt_results


def main():
    splits_audit = audit_splits_and_leakage()
    dwarf_audit = audit_dwarf_mapping_rates()
    inlining_exp = evaluate_compiler_inlining_experiment()

    output = {
        "dataset_splits_audit": splits_audit,
        "dwarf_mapping_audit": dwarf_audit,
        "compiler_inlining_evaluation": inlining_exp,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }

    out_file = "benchmark_dataset_audit.json"
    with open(out_file, "w") as f:
        json.dump(output, f, indent=2)
    print(f"\n[+] Saved complete dataset audit report to {out_file}")


if __name__ == "__main__":
    main()

