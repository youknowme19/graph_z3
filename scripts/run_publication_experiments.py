#!/usr/bin/env python3
"""
run_publication_experiments.py — Complete Publication-Grade Experimental Suite for NeuroZ3
===========================================================================================
Executes all 7 empirical evaluations required for top-tier peer review:
  1. Primary Held-Out Test Evaluation + 1,000x Bootstrap 95% CIs (GraphSAGE vs GAT vs Heuristics)
  2. Per-CWE Breakdown across all 21 CWE families
  3. Cross-Optimization Breakdown (-O0, -O1, -O2, -Os) & Clean Patched (-DOMITBAD) FPR
  4. 5-Fold Stratified Group Cross-Validation
  5. Zero-Shot Unseen-CWE Generalization (holding out CWE126, CWE195, CWE416 completely from training)
  6. 5-Client Non-IID Federated Learning (FedProx mu=0.1 vs FedAvg across 10 communication rounds)
  7. Real-World Stripped System Binary Scalability & Neuro-Symbolic Pruning Evaluation (35+ binaries)

Saves all structured JSON tables to `benchmark_gnn_results.json` for direct LaTeX paper integration.
"""

import os
import sys
import copy
import time
import json
import math
import random
from pathlib import Path
from collections import defaultdict

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.loader import DataLoader
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
)

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from src.ml.gnn_model import create_model
from src.ml.trainer import (
    FocalCrossEntropyLoss,
    load_pt_dataset,
    _split_by_binary,
    _compute_class_weights,
    _evaluate_model,
    _find_optimal_temperature,
    _find_optimal_threshold,
    _extract_cwe,
    _get_group_key,
    train_model,
)
from src.graph.feature_extractor import FEATURE_NAMES, FEATURE_GROUPS


def bootstrap_ci(targets, probs, preds, n_boot=1000, seed=42):
    """Compute 95% bootstrap confidence intervals over node predictions."""
    rng = np.random.default_rng(seed)
    n = len(targets)
    precs, recs, f1s, aucs, aps = [], [], [], [], []
    # Graph-level / stratified block bootstrap via 200 chunks for speed & variance fidelity
    n_chunks = 200
    chunks = np.array_split(np.arange(n), n_chunks)
    for _ in range(n_boot):
        chosen = rng.integers(0, n_chunks, size=n_chunks)
        idx = np.concatenate([chunks[c] for c in chosen])
        bt, bp, bpr = targets[idx], preds[idx], probs[idx]
        if bt.sum() == 0 or bt.sum() == len(bt):
            continue
        p, r, f, _ = precision_recall_fscore_support(bt, bp, average="binary", zero_division=0)
        precs.append(p)
        recs.append(r)
        f1s.append(f)
        aucs.append(roc_auc_score(bt, bpr))
        aps.append(average_precision_score(bt, bpr))

    def _ci(arr):
        return [round(float(np.percentile(arr, 2.5)), 4), round(float(np.percentile(arr, 97.5)), 4)]

    return {
        "precision_ci": _ci(precs),
        "recall_ci": _ci(recs),
        "f1_ci": _ci(f1s),
        "roc_auc_ci": _ci(aucs),
        "ap_ci": _ci(aps),
    }


def evaluate_detailed_subsets(model, dataset_list, device, temp, thresh):
    """Compute per-CWE and per-optimization level metrics on a list of PyG graphs."""
    model.eval()
    by_cwe = defaultdict(lambda: {"y": [], "p": [], "pred": [], "top1": 0, "top5": 0, "v_graphs": 0, "c_graphs": 0})
    by_opt = defaultdict(lambda: {"y": [], "p": [], "pred": [], "top1": 0, "top5": 0, "v_graphs": 0, "c_graphs": 0})

    with torch.no_grad():
        for d in dataset_list:
            cwe = _extract_cwe(d)
            opt = getattr(d, "opt_level", "O0") or "O0"
            dg = d.to(device)
            logits = model(dg.x, dg.edge_index) / temp
            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            preds = (probs >= thresh).astype(np.int64)
            y = d.y.cpu().numpy()

            for bucket in (by_cwe[cwe], by_opt[opt]):
                bucket["y"].append(y)
                bucket["p"].append(probs)
                bucket["pred"].append(preds)
                if y.sum() > 0:
                    bucket["v_graphs"] += 1
                    rk = np.argsort(-probs)
                    if y[rk[:1]].sum() > 0:
                        bucket["top1"] += 1
                    if y[rk[:5]].sum() > 0:
                        bucket["top5"] += 1
                else:
                    bucket["c_graphs"] += 1

    def _summarize(group_map):
        out = {}
        for k, b in sorted(group_map.items()):
            yt = np.concatenate(b["y"])
            yp = np.concatenate(b["p"])
            yd = np.concatenate(b["pred"])
            prec, rec, f1, _ = precision_recall_fscore_support(yt, yd, average="binary", zero_division=0)
            auc = float(roc_auc_score(yt, yp)) if yt.sum() > 0 and yt.sum() < len(yt) else 0.0
            ap = float(average_precision_score(yt, yp)) if yt.sum() > 0 else 0.0
            vg = max(b["v_graphs"], 1)
            out[k] = {
                "vuln_graphs": b["v_graphs"],
                "clean_graphs": b["c_graphs"],
                "total_nodes": int(len(yt)),
                "vuln_nodes": int(yt.sum()),
                "precision": round(float(prec), 4),
                "recall": round(float(rec), 4),
                "f1": round(float(f1), 4),
                "roc_auc": round(auc, 4),
                "pr_auc": round(ap, 4),
                "top1_hit_rate": round(float(b["top1"] / vg), 4),
                "top5_hit_rate": round(float(b["top5"] / vg), 4),
            }
        return out

    return _summarize(by_cwe), _summarize(by_opt)


def evaluate_static_heuristics(test_data):
    """Compare single-feature classical static heuristics on the exact held-out test set."""
    all_x = np.concatenate([d.x.numpy() for d in test_data], axis=0)
    all_y = np.concatenate([d.y.numpy() for d in test_data], axis=0)

    heuristics = {
        "Has Unsafe String / Call (feat 17/19)": np.maximum(all_x[:, 17], all_x[:, 19]),
        "Has Memory Write (Ist_Store, feat 25)": all_x[:, 25],
        "Computed Store + Taint Reachability": (all_x[:, 28] > 0.5).astype(float) * (all_x[:, 31] > 0.3).astype(float),
        "Instruction Complexity (feat 8)": all_x[:, 8] > np.percentile(all_x[:, 8], 95),
        "CFG Flow Centrality (feat 7)": all_x[:, 7] > np.percentile(all_x[:, 7], 95),
    }
    res = {}
    for name, scores in heuristics.items():
        preds = (scores > 0.5).astype(int)
        p, r, f1, _ = precision_recall_fscore_support(all_y, preds, average="binary", zero_division=0)
        res[name] = {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1": round(float(f1), 4),
        }
    return res


def quick_train_and_eval(train_set, val_set, test_set, encoder="sage", epochs=35, hidden_dim=128, num_layers=3, seed=42):
    """Fast reproducible training helper for GAT comparison, k-fold CV, and Zero-Shot CWE experiments."""
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    device = torch.device("cpu")

    model = create_model(
        input_dim=len(FEATURE_NAMES),
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        encoder=encoder,
        dropout=0.25,
    ).to(device)

    weight = _compute_class_weights(train_set, device)
    criterion = FocalCrossEntropyLoss(weight=weight, gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=0.0015, weight_decay=1e-4)

    train_loader = DataLoader(train_set, batch_size=32, shuffle=True)
    val_loader = DataLoader(val_set, batch_size=32, shuffle=False)
    test_loader = DataLoader(test_set, batch_size=32, shuffle=False)

    best_score = -1.0
    best_state = None
    no_imp = 0

    for ep in range(1, epochs + 1):
        model.train()
        for batch in train_loader:
            optimizer.zero_grad()
            out = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

        vm = _evaluate_model(model, val_loader, criterion, device)
        sc = 0.65 * vm["avg_precision"] + 0.35 * vm["top5_hit_rate"]
        if sc > best_score:
            best_score = sc
            best_state = copy.deepcopy(model.state_dict())
            no_imp = 0
        else:
            no_imp += 1
        if no_imp >= 8:
            break

    model.load_state_dict(best_state)
    temp = _find_optimal_temperature(model, val_loader, device)
    thresh = _find_optimal_threshold(model, val_loader, device, temp)
    tm = _evaluate_model(model, test_loader, criterion, device, temperature=temp, threshold=thresh)
    for k in ("_raw_targets", "_raw_preds", "_raw_probs", "per_graph"):
        tm.pop(k, None)
    return tm


def run_5fold_cv(dataset, epochs=30, seed=42):
    """5-Fold Stratified Cross-Validation grouped by (CWE, base_testcase)."""
    rng = random.Random(seed)
    cwe_groups = defaultdict(lambda: defaultdict(list))
    for d in dataset:
        cwe_groups[_extract_cwe(d)][_get_group_key(d)].append(d)

    folds = [[] for _ in range(5)]
    for cwe, gmap in sorted(cwe_groups.items()):
        keys = sorted(gmap.keys())
        rng.shuffle(keys)
        for idx, k in enumerate(keys):
            folds[idx % 5].extend(gmap[k])

    fold_results = []
    for f_idx in range(5):
        print(f"  [CV Fold {f_idx+1}/5] Training & evaluating...", flush=True)
        test_f = folds[f_idx]
        val_f = folds[(f_idx + 1) % 5][: max(1, len(folds[(f_idx + 1) % 5]) // 2)]
        val_ids = set(id(x) for x in val_f)
        train_f = []
        for j in range(5):
            if j == f_idx:
                continue
            for item in folds[j]:
                if id(item) not in val_ids:
                    train_f.append(item)
        res = quick_train_and_eval(train_f, val_f, test_f, encoder="sage", epochs=epochs, seed=seed + f_idx)
        fold_results.append(res)
        print(
            f"    -> Fold {f_idx+1}: F1={res['f1']:.4f}, PR-AUC={res['avg_precision']:.4f}, "
            f"ROC-AUC={res['roc_auc']:.4f}, Top-1={res['top1_hit_rate']*100:.1f}%, Top-5={res['top5_hit_rate']*100:.1f}%",
            flush=True,
        )

    summary = {}
    for metric in ("precision", "recall", "f1", "roc_auc", "avg_precision", "top1_hit_rate", "top5_hit_rate", "clean_binary_fpr"):
        vals = [r[metric] for r in fold_results]
        summary[metric] = {
            "mean": round(float(np.mean(vals)), 4),
            "std": round(float(np.std(vals)), 4),
        }
    return {"folds": fold_results, "summary": summary}


def run_zeroshot_cwe(dataset, heldout_cwes=("CWE126", "CWE195", "CWE416"), epochs=32):
    """Train strictly on seen CWEs and test zero-shot on 3 completely unseen CWE families."""
    seen = [d for d in dataset if _extract_cwe(d) not in heldout_cwes]
    unseen = [d for d in dataset if _extract_cwe(d) in heldout_cwes]
    tr, va, _ = _split_by_binary(seen, train_ratio=0.85, val_ratio=0.15, test_ratio=0.0, seed=42)
    if not va:
        va = tr[-150:]
        tr = tr[:-150]
    res = quick_train_and_eval(tr, va, unseen, encoder="sage", epochs=epochs, seed=101)
    res["heldout_cwes"] = list(heldout_cwes)
    res["num_unseen_graphs"] = len(unseen)
    return res


def run_zeroshot_projects(dataset, heldout_projects=("openssl", "FFmpeg", "tcpdump", "haproxy", "ImageMagick"), epochs=32):
    """Hold out 5 entire real-world open-source C repositories during training and evaluate zero-shot."""
    pv_only = [d for d in dataset if getattr(d, "corpus_source", "") == "primevul_real_cve"]
    if len(pv_only) < 100:
        return {}
    held_lower = {p.lower() for p in heldout_projects}
    seen = [d for d in dataset if str(getattr(d, "project", "")).lower() not in held_lower]
    unseen = [d for d in pv_only if str(getattr(d, "project", "")).lower() in held_lower]
    if len(unseen) < 10:
        return {}
    tr, va, _ = _split_by_binary(seen, train_ratio=0.85, val_ratio=0.15, test_ratio=0.0, seed=42)
    res = quick_train_and_eval(tr, va, unseen, encoder="sage", epochs=epochs, seed=202)
    res["heldout_projects"] = list(heldout_projects)
    res["num_unseen_project_binaries"] = len(unseen)
    return res


def run_federated_non_iid(train_data, val_data, test_data, rounds=10, local_epochs=6, mu=0.002):
    """
    5-Client Non-IID Federated Learning experiment comparing FedProx (mu=0.002) vs FedAvg (mu=0.0).
    Clients hold disjoint vulnerability & repository silos across all training binaries:
      - Client 0: Stack & Out-of-Bounds Memory Safety Silo
      - Client 1: Heap & Pointer Lifecycle Silo
      - Client 2: Arithmetic & Input-Taint Silo
      - Client 3: Linux Kernel Real-World CVE Silo
      - Client 4: User-Space Open-Source Daemons & Libraries CVE Silo
    """
    device = torch.device("cpu")
    buckets = [[] for _ in range(5)]
    for d in train_data:
        cwe = _extract_cwe(d)
        src = str(getattr(d, "corpus_source", ""))
        proj = str(getattr(d, "project", "")).lower()
        if src == "primevul_real_cve":
            if proj == "linux":
                buckets[3].append(d)
            else:
                buckets[4].append(d)
        elif cwe in ("CWE121", "CWE124", "CWE126", "CWE127"):
            buckets[0].append(d)
        elif cwe in ("CWE122", "CWE415", "CWE416", "CWE476", "CWE590", "CWE690", "CWE761", "CWE789"):
            buckets[1].append(d)
        else:
            buckets[2].append(d)

    val_loader = DataLoader(val_data, batch_size=32, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=32, shuffle=False)
    weight = _compute_class_weights(train_data, device)
    criterion = FocalCrossEntropyLoss(weight=weight, gamma=2.0)

    def _run_fl(prox_mu: float, label: str):
        torch.manual_seed(42)
        global_model = create_model(input_dim=len(FEATURE_NAMES), hidden_dim=128, num_layers=3, encoder="sage", dropout=0.25).to(device)
        param_bytes = sum(p.numel() * p.element_size() for p in global_model.parameters())
        round_history = []

        for rnd in range(1, rounds + 1):
            global_params = [p.detach().clone() for p in global_model.parameters()]
            client_states = []
            client_sizes = []
            client_losses = []

            for k_idx, c_data in enumerate(buckets):
                if not c_data:
                    continue
                local_model = copy.deepcopy(global_model)
                opt = optim.AdamW(local_model.parameters(), lr=0.0012, weight_decay=1e-4)
                c_loader = DataLoader(c_data, batch_size=32, shuffle=True)
                local_model.train()
                ep_loss = 0.0
                for _ in range(local_epochs):
                    for batch in c_loader:
                        opt.zero_grad()
                        out = local_model(batch.x, batch.edge_index, batch.batch)
                        loss = criterion(out, batch.y)
                        if prox_mu > 0.0:
                            prox_term = sum(((lp - gp) ** 2).sum() for lp, gp in zip(local_model.parameters(), global_params))
                            loss = loss + 0.5 * prox_mu * prox_term
                        loss.backward()
                        torch.nn.utils.clip_grad_norm_(local_model.parameters(), 1.0)
                        opt.step()
                        ep_loss += float(loss.item()) * batch.num_graphs
                client_losses.append(ep_loss / max(len(c_data) * local_epochs, 1))
                client_states.append({k: v.detach().clone() for k, v in local_model.state_dict().items()})
                client_sizes.append(len(c_data))

            # Sample-weighted aggregation
            total_n = float(sum(client_sizes))
            new_state = {}
            for key in global_model.state_dict().keys():
                if global_model.state_dict()[key].is_floating_point():
                    new_state[key] = sum(st[key] * (sz / total_n) for st, sz in zip(client_states, client_sizes))
                else:
                    new_state[key] = client_states[0][key]
            global_model.load_state_dict(new_state)

            tm = _evaluate_model(global_model, test_loader, criterion, device)
            round_history.append({
                "round": rnd,
                "mean_client_loss": round(float(np.mean(client_losses)), 4),
                "test_loss": round(tm["loss"], 4),
                "test_pr_auc": round(tm["avg_precision"], 4),
                "test_roc_auc": round(tm["roc_auc"], 4),
                "test_f1": round(tm["f1"], 4),
                "test_top1": round(tm["top1_hit_rate"], 4),
                "test_top5": round(tm["top5_hit_rate"], 4),
            })
            print(
                f"  [{label} Round {rnd:02d}/{rounds:02d}] Loss={round_history[-1]['mean_client_loss']:.4f} | "
                f"Test PR-AUC={tm['avg_precision']:.4f} | Top-1={tm['top1_hit_rate']*100:.1f}% | Top-5={tm['top5_hit_rate']*100:.1f}%",
                flush=True,
            )

        temp = _find_optimal_temperature(global_model, val_loader, device)
        thresh = _find_optimal_threshold(global_model, val_loader, device, temp)
        final_tm = _evaluate_model(global_model, test_loader, criterion, device, temperature=temp, threshold=thresh)
        for k in ("_raw_targets", "_raw_preds", "_raw_probs", "per_graph"):
            final_tm.pop(k, None)
        return {
            "rounds": round_history,
            "final_calibrated_test": final_tm,
            "payload_kb_per_client_round": round(param_bytes / 1024.0, 2),
            "client_partition_sizes": [len(b) for b in buckets],
        }

    fedprox_res = _run_fl(mu, f"FedProx(mu={mu})")
    fedavg_res = _run_fl(0.0, "FedAvg(mu=0.0)")
    return {"fedprox": fedprox_res, "fedavg": fedavg_res}


def evaluate_real_world_and_pruning(model, real_dir, test_data, temp, thresh):
    """Evaluate GNN inference speed and symbolic block pruning ratio on real-world & test binaries."""
    device = torch.device("cpu")
    model.eval()

    real_pts = sorted(p for p in Path(real_dir).glob("*.pt") if not p.name.startswith("._"))
    real_stats = []
    infer_times_ms = []

    with torch.no_grad():
        for p in real_pts:
            g = torch.load(p, weights_only=False)
            t0 = time.perf_counter()
            logits = model(g.x, g.edge_index) / temp
            probs = torch.softmax(logits, dim=1)[:, 1].numpy()
            dt_ms = (time.perf_counter() - t0) * 1000.0
            infer_times_ms.append(dt_ms)

            flagged = int((probs >= thresh).sum())
            pruned_pct = (1.0 - (flagged / max(int(g.num_nodes), 1))) * 100.0
            real_stats.append({
                "binary": g.binary_name,
                "nodes": int(g.num_nodes),
                "edges": int(g.num_edges),
                "flagged_candidates": flagged,
                "pruned_pct": round(pruned_pct, 2),
                "gnn_infer_ms": round(dt_ms, 3),
            })

    # Compute pruning ratio on held-out Juliet test set as well
    test_flagged = 0
    test_total_nodes = 0
    test_infer_ms = []
    with torch.no_grad():
        for g in test_data:
            t0 = time.perf_counter()
            logits = model(g.x, g.edge_index) / temp
            probs = torch.softmax(logits, dim=1)[:, 1].numpy()
            test_infer_ms.append((time.perf_counter() - t0) * 1000.0)
            test_flagged += int((probs >= thresh).sum())
            test_total_nodes += int(g.num_nodes)

    return {
        "real_world_binaries_count": len(real_stats),
        "real_world_total_nodes": sum(x["nodes"] for x in real_stats),
        "real_world_total_edges": sum(x["edges"] for x in real_stats),
        "real_world_mean_pruned_pct": round(float(np.mean([x["pruned_pct"] for x in real_stats])) if real_stats else 0.0, 2),
        "real_world_mean_infer_ms": round(float(np.mean(infer_times_ms)) if infer_times_ms else 0.0, 3),
        "test_set_pruned_pct": round((1.0 - test_flagged / max(test_total_nodes, 1)) * 100.0, 2),
        "test_set_mean_infer_ms": round(float(np.mean(test_infer_ms)) if test_infer_ms else 0.0, 3),
        "real_world_per_binary": real_stats,
    }


def main():
    juliet_dir = os.path.join(ROOT_DIR, "data", "processed_graphs")
    primevul_dir = os.path.join(ROOT_DIR, "data", "primevul_graphs")
    real_dir = os.path.join(ROOT_DIR, "data", "real_world_graphs")
    model_path = os.path.join(ROOT_DIR, "model.pt")

    combined_dirs = f"{primevul_dir},{juliet_dir}" if os.path.isdir(primevul_dir) else juliet_dir

    print("=" * 80)
    print("  STEP 1A: Standalone Real-World Open-Source CVE Training (PrimeVul ICSE'24)")
    print("=" * 80)
    pv_standalone_res = {}
    if os.path.isdir(primevul_dir):
        pv_graphs = load_pt_dataset(primevul_dir)
        if len(pv_graphs) >= 50:
            pv_tr, pv_va, pv_te = _split_by_binary(pv_graphs, seed=42)
            pv_standalone_res = quick_train_and_eval(pv_tr, pv_va, pv_te, encoder="sage", epochs=45, seed=42)
            pv_standalone_res["total_real_cve_binaries"] = len(pv_graphs)
            pv_standalone_res["train_graphs"] = len(pv_tr)
            pv_standalone_res["val_graphs"] = len(pv_va)
            pv_standalone_res["test_graphs"] = len(pv_te)
            print(
                f"  -> Pure Real-World CVE Test: ROC-AUC={pv_standalone_res['roc_auc']:.4f}, "
                f"PR-AUC={pv_standalone_res['avg_precision']:.4f}, F1={pv_standalone_res['f1']:.4f}, "
                f"Top-1={pv_standalone_res['top1_hit_rate']*100:.1f}%, Top-5={pv_standalone_res['top5_hit_rate']*100:.1f}%"
            )

    print("\n" + "=" * 80)
    print("  STEP 1B: Primary Unified VulnGNN (Real-World CVEs + Multi-CWE Binaries)")
    print("=" * 80)
    model, primary_test = train_model(
        dataset_dir=combined_dirs,
        epochs=55,
        lr=0.0015,
        model_path=model_path,
        hidden_dim=128,
        num_layers=3,
        encoder="sage",
        dropout=0.25,
        batch_size=32,
        patience=12,
        seed=42,
    )

    dataset = load_pt_dataset(combined_dirs)
    train_data, val_data, test_data = _split_by_binary(dataset, seed=42)
    ckpt = torch.load(model_path, map_location="cpu", weights_only=False)
    temp = ckpt["temperature"]
    thresh = ckpt["threshold"]

    # Re-collect raw test arrays for 1,000x Bootstrap 95% CIs + per-corpus held-out breakdowns
    test_loader = DataLoader(test_data, batch_size=32, shuffle=False)
    eval_raw = _evaluate_model(model, test_loader, FocalCrossEntropyLoss(), torch.device("cpu"), temperature=temp, threshold=thresh)
    cis = bootstrap_ci(eval_raw["_raw_targets"], eval_raw["_raw_probs"], eval_raw["_raw_preds"], n_boot=1000)

    pv_test_subset = [d for d in test_data if getattr(d, "corpus_source", "") == "primevul_real_cve"]
    ju_test_subset = [d for d in test_data if getattr(d, "corpus_source", "") != "primevul_real_cve"]

    pv_subset_metrics = {}
    if pv_test_subset:
        # Calibrate optimal threshold on PrimeVul val subset for domain-specific F1 alongside shared model probabilities
        pv_val_subset = [d for d in val_data if getattr(d, "corpus_source", "") == "primevul_real_cve"]
        pv_th = _find_optimal_threshold(model, DataLoader(pv_val_subset, batch_size=32), torch.device("cpu"), temp) if pv_val_subset else thresh
        pv_m = _evaluate_model(model, DataLoader(pv_test_subset, batch_size=32), FocalCrossEntropyLoss(), torch.device("cpu"), temperature=temp, threshold=pv_th)
        for k in ("_raw_targets", "_raw_preds", "_raw_probs", "per_graph"):
            pv_m.pop(k, None)
        pv_subset_metrics = pv_m

    ju_subset_metrics = {}
    if ju_test_subset:
        ju_val_subset = [d for d in val_data if getattr(d, "corpus_source", "") != "primevul_real_cve"]
        ju_th = _find_optimal_threshold(model, DataLoader(ju_val_subset, batch_size=32), torch.device("cpu"), temp) if ju_val_subset else thresh
        ju_m = _evaluate_model(model, DataLoader(ju_test_subset, batch_size=32), FocalCrossEntropyLoss(), torch.device("cpu"), temperature=temp, threshold=ju_th)
        for k in ("_raw_targets", "_raw_preds", "_raw_probs", "per_graph"):
            ju_m.pop(k, None)
        ju_subset_metrics = ju_m

    print("\n" + "=" * 80)
    print("  STEP 2: Per-CWE & Cross-Optimization Breakdown + Heuristic Baselines")
    print("=" * 80)
    per_cwe_test, per_opt_test = evaluate_detailed_subsets(model, test_data, torch.device("cpu"), temp, thresh)
    heuristics_res = evaluate_static_heuristics(test_data)

    print("  [*] Training GAT (4-Head Graph Attention) ablation comparator...")
    gat_test = quick_train_and_eval(train_data, val_data, test_data, encoder="gat", epochs=40, seed=42)

    print("  [*] Running 5-group Feature Ablation Study (retraining per ablated group)...")
    ablation_res = {}
    for gname, gidxs in FEATURE_GROUPS.items():
        def _mask_list(dlist, idxs):
            out_l = []
            for d in dlist:
                dc = d.clone()
                dc.x = dc.x.clone()
                dc.x[:, idxs] = 0.0
                out_l.append(dc)
            return out_l
        ab_m = quick_train_and_eval(
            _mask_list(train_data, gidxs),
            _mask_list(val_data, gidxs),
            _mask_list(test_data, gidxs),
            encoder="sage",
            epochs=30,
            seed=42,
        )
        ablation_res[f"w/o_{gname}"] = {
            "f1": ab_m["f1"],
            "precision": ab_m["precision"],
            "recall": ab_m["recall"],
            "pr_auc": ab_m["avg_precision"],
            "roc_auc": ab_m["roc_auc"],
            "top1_hit_rate": ab_m["top1_hit_rate"],
            "top5_hit_rate": ab_m["top5_hit_rate"],
        }
        print(f"    -> w/o {gname:12s}: F1={ab_m['f1']:.4f}, PR-AUC={ab_m['avg_precision']:.4f}, Top-1={ab_m['top1_hit_rate']*100:.1f}%")

    print("\n" + "=" * 80)
    print("  STEP 3: 5-Fold Stratified Group Cross-Validation")
    print("=" * 80)
    cv_res = run_5fold_cv(dataset, epochs=28, seed=42)

    print("\n" + "=" * 80)
    print("  STEP 4: Zero-Shot Unseen CWE & Unseen Real-World Repository Generalization")
    print("=" * 80)
    zeroshot_res = run_zeroshot_cwe(dataset, heldout_cwes=("CWE126", "CWE195", "CWE416"), epochs=30)
    print(f"  -> Zero-Shot Unseen CWE ROC-AUC={zeroshot_res['roc_auc']:.4f}, PR-AUC={zeroshot_res['avg_precision']:.4f}, Top-5={zeroshot_res['top5_hit_rate']*100:.1f}%, Top-10={zeroshot_res['top10_hit_rate']*100:.1f}%")
    zeroshot_proj_res = run_zeroshot_projects(dataset, heldout_projects=("openssl", "FFmpeg", "tcpdump", "haproxy", "ImageMagick"), epochs=30)
    if zeroshot_proj_res:
        print(f"  -> Zero-Shot Unseen OSS Projects ({zeroshot_proj_res['num_unseen_project_binaries']} bins): ROC-AUC={zeroshot_proj_res['roc_auc']:.4f}, Top-1={zeroshot_proj_res['top1_hit_rate']*100:.1f}%, Top-5={zeroshot_proj_res['top5_hit_rate']*100:.1f}%")

    print("\n" + "=" * 80)
    print("  STEP 5: 5-Client Non-IID Federated Learning (FedProx mu=0.002 vs FedAvg)")
    print("=" * 80)
    fl_res = run_federated_non_iid(train_data, val_data, test_data, rounds=10, local_epochs=6, mu=0.002)

    print("\n" + "=" * 80)
    print("  STEP 6: Real-World System Binaries & Neuro-Symbolic Pruning Analysis")
    print("=" * 80)
    real_pruning_res = evaluate_real_world_and_pruning(model, real_dir, test_data, temp, thresh)

    # Load corpus censuses
    ju_stats_file = os.path.join(juliet_dir, "dataset_stats.json")
    pv_stats_file = os.path.join(primevul_dir, "primevul_dataset_stats.json")
    corpus_stats = {
        "primevul_real_cve": json.load(open(pv_stats_file)) if os.path.exists(pv_stats_file) else {},
        "juliet_multi_cwe": json.load(open(ju_stats_file)) if os.path.exists(ju_stats_file) else {},
    }

    full_report = {
        "corpus_summary": corpus_stats,
        "split_sizes": {
            "total_combined_graphs": len(dataset),
            "primevul_real_cve_graphs": sum(1 for d in dataset if getattr(d, "corpus_source", "") == "primevul_real_cve"),
            "juliet_multi_cwe_graphs": sum(1 for d in dataset if getattr(d, "corpus_source", "") != "primevul_real_cve"),
            "train_graphs": len(train_data),
            "val_graphs": len(val_data),
            "test_graphs": len(test_data),
            "test_total_nodes": sum(int(d.num_nodes) for d in test_data),
            "test_vuln_nodes": sum(int(d.y.sum()) for d in test_data),
        },
        "primevul_standalone_real_cve_test": pv_standalone_res,
        "primary_heldout_test": {k: v for k, v in primary_test.items() if k != "per_graph"},
        "primevul_heldout_subset_test": pv_subset_metrics,
        "juliet_heldout_subset_test": ju_subset_metrics,
        "bootstrap_95_ci": cis,
        "gat_ablation_test": gat_test,
        "feature_group_ablation": ablation_res,
        "heuristic_baselines": heuristics_res,
        "per_cwe_test": per_cwe_test,
        "per_optimization_test": per_opt_test,
        "five_fold_cv": cv_res,
        "zeroshot_unseen_cwe": zeroshot_res,
        "zeroshot_unseen_projects": zeroshot_proj_res,
        "federated_non_iid": fl_res,
        "real_world_and_pruning": real_pruning_res,
    }

    out_json = os.path.join(ROOT_DIR, "benchmark_gnn_results.json")
    with open(out_json, "w") as f:
        json.dump(full_report, f, indent=2)

    print("\n" + "=" * 80)
    print(f"  ALL PUBLICATION EXPERIMENTS COMPLETE! Saved -> {out_json}")
    print("=" * 80)


def update_fl_and_census_only():
    from collections import Counter
    primevul_dir = os.path.join(ROOT_DIR, "data", "primevul_graphs")
    juliet_dir = os.path.join(ROOT_DIR, "data", "processed_graphs")

    # Recompute exact census across all 2,480 PrimeVul .pt graphs on disk
    pv_pts = sorted(p for p in Path(primevul_dir).glob("*.pt") if not p.name.startswith("._"))
    projs = Counter()
    cwes = Counter()
    cves = set()
    base_pairs = set()
    vuln_bins = 0
    fixed_bins = 0
    tot_nodes = 0
    tot_edges = 0
    tot_vblocks = 0
    for p in pv_pts:
        g = torch.load(p, map_location="cpu", weights_only=False)
        proj = str(getattr(g, "project", "unknown"))
        cwe = str(getattr(g, "cwe", "CWE000"))
        cve = str(getattr(g, "cve", ""))
        bt = str(getattr(g, "base_testcase", p.stem))
        projs[proj] += 1
        cwes[cwe] += 1
        if cve and cve != "N/A":
            cves.add(cve)
        base_pairs.add(bt)
        if bool(getattr(g, "is_patched", False)):
            fixed_bins += 1
        else:
            vuln_bins += 1
        tot_nodes += int(g.x.shape[0])
        tot_edges += int(g.edge_index.shape[1])
        tot_vblocks += int(g.y.sum().item())

    pv_stats = {
        "corpus": "PrimeVul Real-World Open-Source C CVEs (ICSE 2024)",
        "compiled_cve_pairs": len(base_pairs),
        "total_real_cve_binaries": len(pv_pts),
        "vulnerable_pre_patch_binaries": vuln_bins,
        "fixed_post_patch_binaries": fixed_bins,
        "unique_real_projects": len(projs),
        "unique_cves": len(cves),
        "unique_cwes": len(cwes),
        "total_basic_blocks": tot_nodes,
        "total_cfg_edges": tot_edges,
        "total_dwarf_vuln_blocks": tot_vblocks,
        "top_projects": dict(projs.most_common(25)),
        "cwe_distribution": dict(cwes.most_common(36)),
    }
    pv_stats_file = os.path.join(primevul_dir, "primevul_dataset_stats.json")
    with open(pv_stats_file, "w") as f:
        json.dump(pv_stats, f, indent=2)
    print(f"[+] Updated exact PrimeVul census ({len(pv_pts)} binaries, {tot_nodes} blocks, {tot_vblocks} vuln blocks)")

    dataset = load_pt_dataset([primevul_dir, juliet_dir])
    train_data, val_data, test_data = _split_by_binary(
        dataset, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42
    )
    print(f"[+] Running refined 5-client Non-IID FL (local_epochs=6, mu=0.002 vs 0.0)...")
    fl_res = run_federated_non_iid(train_data, val_data, test_data, rounds=10, local_epochs=6, mu=0.002)

    out_json = os.path.join(ROOT_DIR, "benchmark_gnn_results.json")
    with open(out_json) as f:
        report = json.load(f)
    report["corpus_summary"]["primevul_real_cve"] = pv_stats
    report["federated_non_iid"] = fl_res
    with open(out_json, "w") as f:
        json.dump(report, f, indent=2)
    print(f"[+] Merged exact census + refined FL results into {out_json}")


if __name__ == "__main__":
    if "--update-fl-and-census" in sys.argv:
        update_fl_and_census_only()
    else:
        main()

