#!/usr/bin/env python3
"""
run_baselines_and_ablations.py — Publication Baseline & Ablation Suite for NeuroZ3 (Phase 3)
==========================================================================================
Executes the comprehensive baseline and ablation experiments required for peer-reviewed publication:
  1. Baselines:
     - Random Ranking (analytical expectation and empirical uniform sampling)
     - Classical Static Heuristics (Unsafe Call, Store Density, Taint Reachability, Flow Centrality)
     - XGBoost (gradient boosted trees on 40-D node features)
     - MLP Baseline (3-layer MLP node classifier without graph message passing)
     - Unidirectional GraphSAGE (forward CFG edges only)
     - GIN (Bidirectional Graph Isomorphism Network with sum-aggregation)
     - VulnGNN (Proposed: Bidirectional GraphSAGE + Global Context + Feature Gate)
  2. Ranking Evaluation:
     - Mean Reciprocal Rank (MRR)
     - Top-1, Top-3, Top-5, Top-10 Hit Rates
     - Normalized Top-K (fraction of basic blocks traversed)
     - Ranking Lift over Random, MLP, and XGBoost
  3. Architectural Ablations:
     - Full VulnGNN vs w/o Global Context vs w/o Feature Gate vs Unidirectional vs GAT
  4. Feature-Group Ablations:
     - Leave-one-group-out (w/o Structural, w/o Instruction, w/o Semantic, w/o Dataflow, w/o Symbolic)
     - Group-only (Structural only, Instruction only, Semantic only, Dataflow only, Symbolic only)
  5. Multi-Corpus Generalization:
     - Combined Test Set (775 graphs)
     - Juliet Held-Out Test Set (403 graphs)
     - PrimeVul Real-World CVE Held-Out Test Set (372 graphs)
     - Zero-Shot Real-World System Binaries (39 binaries, including nm-classic, size-classic, m4, strings)

Outputs structured, reproducible results to `benchmark_baselines_ablations.json`
and updates `benchmark_gnn_results.json`.
"""

import os
import sys
import copy
import time
import json
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
import xgboost as xgb

SCRIPT_DIR = os.path.abspath(os.path.dirname(__file__))
ROOT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
SRC_DIR = os.path.join(ROOT_DIR, "src")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from src.ml.gnn_model import (
    VulnGNN,
    MLPBaseline,
    UnidirectionalVulnGNN,
    GINVulnGNN,
    create_model,
)
from src.ml.trainer import (
    FocalCrossEntropyLoss,
    load_pt_dataset,
    _split_by_binary,
    _compute_class_weights,
    _find_optimal_temperature,
    _find_optimal_threshold,
)
from src.graph.feature_extractor import FEATURE_NAMES, FEATURE_GROUPS


def set_seed(seed=42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def evaluate_graph_ranking(targets_list, probs_list, preds_list=None):
    """
    Computes graph-level ranking metrics (MRR, Top-1, 3, 5, 10, normalized Top-K)
    and node-level classification metrics across a list of per-graph numpy arrays.
    """
    all_targets = []
    all_probs = []
    all_preds = []

    vuln_graph_count = 0
    clean_graph_count = 0
    clean_graph_false_alarms = 0

    top1_hits = 0
    top3_hits = 0
    top5_hits = 0
    top10_hits = 0
    mrr_sum = 0.0
    norm_top_k_sum = 0.0

    for idx, (y, p) in enumerate(zip(targets_list, probs_list)):
        all_targets.append(y)
        all_probs.append(p)
        pred = (p >= 0.5).astype(np.int64) if preds_list is None else preds_list[idx]
        all_preds.append(pred)

        n_nodes = len(y)
        n_vuln = int(y.sum())

        if n_vuln > 0:
            vuln_graph_count += 1
            rk = np.argsort(-p)
            if y[rk[:1]].sum() > 0:
                top1_hits += 1
            if y[rk[:3]].sum() > 0:
                top3_hits += 1
            if y[rk[:5]].sum() > 0:
                top5_hits += 1
            if y[rk[:10]].sum() > 0:
                top10_hits += 1

            vuln_positions = np.where(y[rk] == 1)[0]
            if len(vuln_positions) > 0:
                first_rank = vuln_positions[0] + 1
                mrr_sum += 1.0 / float(first_rank)
                norm_top_k_sum += float(first_rank) / max(float(n_nodes), 1.0)
        else:
            clean_graph_count += 1
            if int(pred.sum()) > 0:
                clean_graph_false_alarms += 1

    yt = np.concatenate(all_targets) if all_targets else np.array([])
    yp = np.concatenate(all_probs) if all_probs else np.array([])
    yd = np.concatenate(all_preds) if all_preds else np.array([])

    prec, rec, f1, _ = precision_recall_fscore_support(yt, yd, average="binary", zero_division=0)
    try:
        roc_auc = float(roc_auc_score(yt, yp)) if yt.sum() > 0 and yt.sum() < len(yt) else 0.0
    except Exception:
        roc_auc = 0.0
    try:
        pr_auc = float(average_precision_score(yt, yp)) if yt.sum() > 0 else 0.0
    except Exception:
        pr_auc = 0.0

    vg = max(vuln_graph_count, 1)
    cg = max(clean_graph_count, 1)

    return {
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc), 4),
        "pr_auc": round(float(pr_auc), 4),
        "top1_hit_rate": round(float(top1_hits / vg), 4),
        "top3_hit_rate": round(float(top3_hits / vg), 4),
        "top5_hit_rate": round(float(top5_hits / vg), 4),
        "top10_hit_rate": round(float(top10_hits / vg), 4),
        "mrr": round(float(mrr_sum / vg), 4),
        "normalized_inspection_depth": round(float(norm_top_k_sum / vg), 4),
        "vuln_graphs": int(vuln_graph_count),
        "clean_graphs": int(clean_graph_count),
        "clean_binary_fpr": round(float(clean_graph_false_alarms / cg), 4),
    }


def evaluate_random_baseline(dataset, seed=42, n_trials=50):
    """
    Computes analytical expectation and empirical uniform permutation ranking
    for basic blocks within each binary graph.
    """
    rng = np.random.default_rng(seed)
    vuln_graphs = [d for d in dataset if d.y.sum().item() > 0]
    clean_graphs = [d for d in dataset if d.y.sum().item() == 0]

    # Analytical calculations
    analytical_top1 = []
    analytical_top3 = []
    analytical_top5 = []
    analytical_top10 = []
    analytical_expected_rank = []

    for d in vuln_graphs:
        n = int(d.num_nodes)
        v = int(d.y.sum().item())
        # Probability of at least one vuln node in top K: 1 - prod_{j=0}^{K-1} (1 - v/(n-j))
        def _prob_top_k(k):
            if k >= n:
                return 1.0
            prod = 1.0
            for j in range(k):
                prod *= (n - v - j) / float(n - j)
            return 1.0 - prod

        analytical_top1.append(_prob_top_k(1))
        analytical_top3.append(_prob_top_k(3))
        analytical_top5.append(_prob_top_k(5))
        analytical_top10.append(_prob_top_k(10))
        analytical_expected_rank.append((n + 1.0) / float(v + 1.0))

    # Empirical calculations (averaged over n_trials)
    emp_top1 = 0
    emp_top3 = 0
    emp_top5 = 0
    emp_top10 = 0
    emp_mrr_sum = 0.0

    for d in vuln_graphs:
        y = d.y.cpu().numpy()
        n = len(y)
        for _ in range(n_trials):
            perm = rng.permutation(n)
            y_perm = y[perm]
            if y_perm[:1].sum() > 0:
                emp_top1 += 1
            if y_perm[:3].sum() > 0:
                emp_top3 += 1
            if y_perm[:5].sum() > 0:
                emp_top5 += 1
            if y_perm[:10].sum() > 0:
                emp_top10 += 1
            first_idx = np.where(y_perm == 1)[0][0] + 1
            emp_mrr_sum += 1.0 / float(first_idx)

    total_samples = max(len(vuln_graphs) * n_trials, 1)

    all_y = np.concatenate([d.y.cpu().numpy() for d in dataset])
    prior = float(all_y.mean()) if len(all_y) > 0 else 0.0

    return {
        "precision": round(prior, 4),
        "recall": 0.5000,
        "f1": round(2 * prior / (1 + prior) if prior > 0 else 0.0, 4),
        "roc_auc": 0.5000,
        "pr_auc": round(prior, 4),
        "top1_hit_rate": round(float(emp_top1 / total_samples), 4),
        "top3_hit_rate": round(float(emp_top3 / total_samples), 4),
        "top5_hit_rate": round(float(emp_top5 / total_samples), 4),
        "top10_hit_rate": round(float(emp_top10 / total_samples), 4),
        "mrr": round(float(emp_mrr_sum / total_samples), 4),
        "clean_binary_fpr": 0.5000,
        "analytical": {
            "expected_top1": round(float(np.mean(analytical_top1)), 4),
            "expected_top3": round(float(np.mean(analytical_top3)), 4),
            "expected_top5": round(float(np.mean(analytical_top5)), 4),
            "expected_top10": round(float(np.mean(analytical_top10)), 4),
            "expected_first_rank": round(float(np.mean(analytical_expected_rank)), 2),
        },
    }


def evaluate_static_heuristics(dataset):
    """Evaluates classical rule-based static binary heuristics."""
    targets_list = [d.y.cpu().numpy() for d in dataset]
    x_list = [d.x.cpu().numpy() for d in dataset]

    heuristics = {
        "Unsafe Call / String Sink": lambda x: np.maximum(x[:, 17], x[:, 19]),
        "Memory Write Density": lambda x: x[:, 25],
        "Taint Sink Reachability": lambda x: (x[:, 28] > 0.5).astype(float) * (x[:, 31] > 0.3).astype(float),
        "CFG Flow Centrality": lambda x: (x[:, 7] > 0.6).astype(float),
    }

    results = {}
    for hname, hfn in heuristics.items():
        probs_list = [hfn(x) for x in x_list]
        m = evaluate_graph_ranking(targets_list, probs_list)
        results[hname] = m
    return results


def train_and_eval_xgboost(train_data, val_data, test_data, feature_mask=None, seed=42):
    """Trains and evaluates node-level XGBoost classifier with per-graph ranking."""
    t0 = time.perf_counter()
    X_tr = np.concatenate([d.x.cpu().numpy() for d in train_data], axis=0)
    y_tr = np.concatenate([d.y.cpu().numpy() for d in train_data], axis=0)

    X_va = np.concatenate([d.x.cpu().numpy() for d in val_data], axis=0)
    y_va = np.concatenate([d.y.cpu().numpy() for d in val_data], axis=0)

    if feature_mask is not None:
        X_tr = X_tr[:, feature_mask]
        X_va = X_va[:, feature_mask]

    n_pos = int(y_tr.sum())
    n_neg = len(y_tr) - n_pos
    scale_pos = float(n_neg / max(n_pos, 1))

    clf = xgb.XGBClassifier(
        n_estimators=120,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos,
        eval_metric="logloss",
        random_state=seed,
        n_jobs=4,
    )
    clf.fit(X_tr, y_tr)

    # Calibrate threshold on validation set
    va_probs = clf.predict_proba(X_va)[:, 1]
    best_th = 0.5
    best_f1 = -1.0
    for th in np.linspace(0.1, 0.9, 17):
        p, r, f1, _ = precision_recall_fscore_support(y_va, (va_probs >= th).astype(int), average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_th = float(th)

    train_time_s = time.perf_counter() - t0

    # Evaluate on test set
    t_inf0 = time.perf_counter()
    targets_list = [d.y.cpu().numpy() for d in test_data]
    probs_list = []
    preds_list = []

    for d in test_data:
        x_mat = d.x.cpu().numpy()
        if feature_mask is not None:
            x_mat = x_mat[:, feature_mask]
        p = clf.predict_proba(x_mat)[:, 1]
        probs_list.append(p)
        preds_list.append((p >= best_th).astype(np.int64))

    infer_time_ms = ((time.perf_counter() - t_inf0) / max(len(test_data), 1)) * 1000.0

    metrics = evaluate_graph_ranking(targets_list, probs_list, preds_list)
    metrics["optimal_threshold"] = round(best_th, 3)
    metrics["train_time_sec"] = round(train_time_s, 2)
    metrics["infer_ms_per_graph"] = round(infer_time_ms, 3)
    return metrics, clf


def train_and_eval_neural(
    model_type,
    train_data,
    val_data,
    test_data,
    epochs=25,
    batch_size=64,
    lr=0.0015,
    patience=6,
    seed=42,
    feature_mask=None,
    device="cpu",
    **model_kwargs
):
    """
    Unified training and evaluation pipeline for MLP, Unidirectional SAGE, GIN, and VulnGNN.
    Applies Focal Loss, AdamW, validation checkpointing, post-hoc temperature scaling,
    and threshold optimization.
    """
    set_seed(seed)
    dev = torch.device(device)
    t0 = time.perf_counter()

    in_dim = len(feature_mask) if feature_mask is not None else len(FEATURE_NAMES)
    model = create_model(input_dim=in_dim, model_type=model_type, **model_kwargs).to(dev)

    weight = _compute_class_weights(train_data, dev)
    criterion = FocalCrossEntropyLoss(weight=weight, gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

    def _prep_batch(batch):
        b = batch.clone()
        if feature_mask is not None:
            b.x = b.x[:, feature_mask]
        return b.to(dev)

    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=batch_size, shuffle=False)

    best_score = -1.0
    best_state = None
    no_improve = 0

    for epoch in range(1, epochs + 1):
        model.train()
        for batch in train_loader:
            b = _prep_batch(batch)
            optimizer.zero_grad()
            out = model(b.x, b.edge_index, b.batch)
            loss = criterion(out, b.y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

        # Validation evaluation
        model.eval()
        va_probs = []
        va_targets = []
        with torch.no_grad():
            for batch in val_loader:
                b = _prep_batch(batch)
                out = model(b.x, b.edge_index, b.batch)
                p = torch.softmax(out, dim=1)[:, 1]
                va_probs.append(p.cpu().numpy())
                va_targets.append(b.y.cpu().numpy())

        yt_va = np.concatenate(va_targets)
        yp_va = np.concatenate(va_probs)
        try:
            ap = float(average_precision_score(yt_va, yp_va))
        except Exception:
            ap = 0.0

        if ap > best_score:
            best_score = ap
            best_state = copy.deepcopy(model.state_dict())
            no_improve = 0
        else:
            no_improve += 1
            if no_improve >= patience:
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    # Post-hoc Temperature and Threshold Calibration
    model.eval()
    va_logits = []
    with torch.no_grad():
        for batch in val_loader:
            b = _prep_batch(batch)
            out = model(b.x, b.edge_index, b.batch)
            va_logits.append(out.cpu())
    all_va_logits = torch.cat(va_logits, dim=0)
    all_va_targets = torch.from_numpy(yt_va)

    best_temp = 1.0
    best_nll = float("inf")
    for temp in np.linspace(0.5, 3.0, 26):
        scaled = all_va_logits / float(temp)
        probs = torch.softmax(scaled, dim=1)
        nll = -torch.log(probs[torch.arange(len(all_va_targets)), all_va_targets] + 1e-8).mean().item()
        if nll < best_nll:
            best_nll = nll
            best_temp = float(temp)

    # Optimal threshold for F1
    scaled_va_probs = torch.softmax(all_va_logits / best_temp, dim=1)[:, 1].numpy()
    best_th = 0.5
    best_f1 = -1.0
    for th in np.linspace(0.1, 0.9, 17):
        p, r, f1, _ = precision_recall_fscore_support(yt_va, (scaled_va_probs >= th).astype(int), average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_th = float(th)

    train_time_s = time.perf_counter() - t0

    # Evaluate on test set
    t_inf0 = time.perf_counter()
    targets_list = []
    probs_list = []
    preds_list = []

    with torch.no_grad():
        for d in test_data:
            dg = d.clone()
            if feature_mask is not None:
                dg.x = dg.x[:, feature_mask]
            dg = dg.to(dev)
            logits = model(dg.x, dg.edge_index) / best_temp
            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            targets = dg.y.cpu().numpy()
            preds = (probs >= best_th).astype(np.int64)

            targets_list.append(targets)
            probs_list.append(probs)
            preds_list.append(preds)

    infer_time_ms = ((time.perf_counter() - t_inf0) / max(len(test_data), 1)) * 1000.0

    metrics = evaluate_graph_ranking(targets_list, probs_list, preds_list)
    metrics["temperature"] = round(best_temp, 3)
    metrics["optimal_threshold"] = round(best_th, 3)
    metrics["train_time_sec"] = round(train_time_s, 2)
    metrics["infer_ms_per_graph"] = round(infer_time_ms, 3)
    return metrics, model


def compute_ranking_lift(model_metrics, baseline_metrics):
    """Computes percentage ranking lift over a baseline."""
    lifts = {}
    for metric in ("mrr", "top1_hit_rate", "top3_hit_rate", "top5_hit_rate", "top10_hit_rate", "pr_auc"):
        m_val = model_metrics.get(metric, 0.0)
        b_val = baseline_metrics.get(metric, 0.0)
        lift = ((m_val - b_val) / max(b_val, 1e-6)) * 100.0
        lifts[f"{metric}_lift_pct"] = round(float(lift), 2)
    return lifts


def main():
    print("=" * 80)
    print("  NEUROZ3 PHASE 3: COMPREHENSIVE BASELINES & ABLATIONS SUITE")
    print("=" * 80)

    juliet_dir = os.path.join(ROOT_DIR, "data", "processed_graphs")
    primevul_dir = os.path.join(ROOT_DIR, "data", "primevul_graphs")
    real_dir = os.path.join(ROOT_DIR, "data", "real_world_graphs")

    print(f"[*] Loading Juliet Multi-CWE dataset from {juliet_dir}...")
    ju_dataset = load_pt_dataset(juliet_dir)
    print(f"[*] Loading PrimeVul Real-CVE dataset from {primevul_dir}...")
    pv_dataset = load_pt_dataset(primevul_dir)

    print(f"[*] Total Juliet graphs: {len(ju_dataset)}, Total PrimeVul graphs: {len(pv_dataset)}")

    # Split Juliet and PrimeVul independently with fixed seed=42 to guarantee zero cross-leakage
    ju_tr, ju_va, ju_te = _split_by_binary(ju_dataset, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)
    pv_tr, pv_va, pv_te = _split_by_binary(pv_dataset, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)

    # Combined dataset splits
    combined_tr = ju_tr + pv_tr
    combined_va = ju_va + pv_va
    combined_te = ju_te + pv_te

    print(f"[+] Dataset Split Summary:")
    print(f"    - Juliet:   Train={len(ju_tr)}, Val={len(ju_va)}, Test={len(ju_te)}")
    print(f"    - PrimeVul: Train={len(pv_tr)}, Val={len(pv_va)}, Test={len(pv_te)}")
    print(f"    - Combined: Train={len(combined_tr)}, Val={len(combined_va)}, Test={len(combined_te)}")

    results = {
        "dataset_split_summary": {
            "juliet": {"train": len(ju_tr), "val": len(ju_va), "test": len(ju_te)},
            "primevul": {"train": len(pv_tr), "val": len(pv_va), "test": len(pv_te)},
            "combined": {"train": len(combined_tr), "val": len(combined_va), "test": len(combined_te)},
        },
        "baselines": {},
        "architectural_ablations": {},
        "feature_group_ablations": {
            "leave_one_group_out": {},
            "group_only": {},
        },
        "corpus_breakdown": {},
        "ranking_lifts": {},
    }

    # =========================================================================
    # 1. BASELINE EVALUATION ON COMBINED HELD-OUT TEST SET
    # =========================================================================
    print("\n" + "=" * 80)
    print("  [1/4] EVALUATING BASELINE ARCHITECTURES (Combined Held-Out Test)")
    print("=" * 80)

    # 1.1 Random Ranking
    print("[*] Running Random Ranking baseline (analytical & empirical 50 trials)...")
    random_res = evaluate_random_baseline(combined_te, seed=42, n_trials=50)
    results["baselines"]["Random Ranking"] = random_res
    print(f"    -> Random: MRR={random_res['mrr']:.4f}, Top-1={random_res['top1_hit_rate']*100:.1f}%, Top-5={random_res['top5_hit_rate']*100:.1f}%")

    # 1.2 Classical Static Heuristics
    print("[*] Evaluating Classical Static Heuristics...")
    heuristics_res = evaluate_static_heuristics(combined_te)
    results["baselines"]["Static Heuristics"] = heuristics_res
    for hn, hm in heuristics_res.items():
        print(f"    -> {hn:30s}: F1={hm['f1']:.4f}, PR-AUC={hm['pr_auc']:.4f}, MRR={hm['mrr']:.4f}, Top-1={hm['top1_hit_rate']*100:.1f}%")

    # 1.3 XGBoost on 40-D features
    print("[*] Training & Evaluating XGBoost node-level baseline...")
    xgb_res, xgb_model = train_and_eval_xgboost(combined_tr, combined_va, combined_te, seed=42)
    results["baselines"]["XGBoost"] = xgb_res
    print(f"    -> XGBoost: F1={xgb_res['f1']:.4f}, PR-AUC={xgb_res['pr_auc']:.4f}, ROC-AUC={xgb_res['roc_auc']:.4f}, MRR={xgb_res['mrr']:.4f}, Top-1={xgb_res['top1_hit_rate']*100:.1f}%, Top-5={xgb_res['top5_hit_rate']*100:.1f}%")

    # 1.4 MLP Baseline (3 layers, no graph edges)
    print("[*] Training & Evaluating 3-Layer MLP Baseline (Node-features only)...")
    mlp_res, mlp_model = train_and_eval_neural("mlp", combined_tr, combined_va, combined_te, epochs=25, seed=42)
    results["baselines"]["MLP (No Graph)"] = mlp_res
    print(f"    -> MLP:     F1={mlp_res['f1']:.4f}, PR-AUC={mlp_res['pr_auc']:.4f}, ROC-AUC={mlp_res['roc_auc']:.4f}, MRR={mlp_res['mrr']:.4f}, Top-1={mlp_res['top1_hit_rate']*100:.1f}%, Top-5={mlp_res['top5_hit_rate']*100:.1f}%")

    # 1.5 Unidirectional GraphSAGE (Forward CFG edges only)
    print("[*] Training & Evaluating Unidirectional GraphSAGE Baseline...")
    unidir_res, unidir_model = train_and_eval_neural("unidirectional", combined_tr, combined_va, combined_te, epochs=25, seed=42)
    results["baselines"]["Unidirectional GraphSAGE"] = unidir_res
    print(f"    -> Uni-SAGE: F1={unidir_res['f1']:.4f}, PR-AUC={unidir_res['pr_auc']:.4f}, ROC-AUC={unidir_res['roc_auc']:.4f}, MRR={unidir_res['mrr']:.4f}, Top-1={unidir_res['top1_hit_rate']*100:.1f}%, Top-5={unidir_res['top5_hit_rate']*100:.1f}%")

    # 1.6 GIN (Bidirectional Graph Isomorphism Network)
    print("[*] Training & Evaluating Bidirectional GIN Baseline...")
    gin_res, gin_model = train_and_eval_neural("gin", combined_tr, combined_va, combined_te, epochs=25, seed=42)
    results["baselines"]["GIN (Bidirectional)"] = gin_res
    print(f"    -> GIN:      F1={gin_res['f1']:.4f}, PR-AUC={gin_res['pr_auc']:.4f}, ROC-AUC={gin_res['roc_auc']:.4f}, MRR={gin_res['mrr']:.4f}, Top-1={gin_res['top1_hit_rate']*100:.1f}%, Top-5={gin_res['top5_hit_rate']*100:.1f}%")

    # 1.7 VulnGNN (Proposed: Bidirectional GraphSAGE + Global Ctx + Feature Gate)
    print("[*] Training & Evaluating Full Proposed VulnGNN (Bi-SAGE + Ctx + Gate)...")
    vulngnn_res, vulngnn_model = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, encoder="sage", epochs=30, seed=42)
    results["baselines"]["VulnGNN (Proposed)"] = vulngnn_res
    print(f"    -> VulnGNN:  F1={vulngnn_res['f1']:.4f}, PR-AUC={vulngnn_res['pr_auc']:.4f}, ROC-AUC={vulngnn_res['roc_auc']:.4f}, MRR={vulngnn_res['mrr']:.4f}, Top-1={vulngnn_res['top1_hit_rate']*100:.1f}%, Top-5={vulngnn_res['top5_hit_rate']*100:.1f}%")

    # Compute ranking lifts of VulnGNN over Baselines
    results["ranking_lifts"]["over_random"] = compute_ranking_lift(vulngnn_res, random_res)
    results["ranking_lifts"]["over_mlp"] = compute_ranking_lift(vulngnn_res, mlp_res)
    results["ranking_lifts"]["over_xgboost"] = compute_ranking_lift(vulngnn_res, xgb_res)
    results["ranking_lifts"]["over_unidirectional"] = compute_ranking_lift(vulngnn_res, unidir_res)

    print("\n[+] Ranking Lift of VulnGNN:")
    print(f"    - Over Random:       MRR Lift = +{results['ranking_lifts']['over_random']['mrr_lift_pct']:.1f}%, Top-1 Lift = +{results['ranking_lifts']['over_random']['top1_hit_rate_lift_pct']:.1f}%")
    print(f"    - Over MLP (Graph):  MRR Lift = +{results['ranking_lifts']['over_mlp']['mrr_lift_pct']:.1f}%, Top-1 Lift = +{results['ranking_lifts']['over_mlp']['top1_hit_rate_lift_pct']:.1f}%")
    print(f"    - Over XGBoost:      MRR Lift = +{results['ranking_lifts']['over_xgboost']['mrr_lift_pct']:.1f}%, Top-1 Lift = +{results['ranking_lifts']['over_xgboost']['top1_hit_rate_lift_pct']:.1f}%")
    print(f"    - Over Uni-SAGE (Bi): MRR Lift = +{results['ranking_lifts']['over_unidirectional']['mrr_lift_pct']:.1f}%, Top-1 Lift = +{results['ranking_lifts']['over_unidirectional']['top1_hit_rate_lift_pct']:.1f}%")

    # =========================================================================
    # 2. ARCHITECTURAL ABLATIONS
    # =========================================================================
    print("\n" + "=" * 80)
    print("  [2/4] ARCHITECTURAL ABLATIONS")
    print("=" * 80)

    # 2.1 w/o Global Context
    print("[*] Evaluating VulnGNN w/o Global Context...")
    no_ctx_res, _ = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, encoder="sage", use_global_ctx=False, epochs=25, seed=42)
    results["architectural_ablations"]["w/o Global Context"] = no_ctx_res
    print(f"    -> w/o Ctx:  F1={no_ctx_res['f1']:.4f}, PR-AUC={no_ctx_res['pr_auc']:.4f}, MRR={no_ctx_res['mrr']:.4f}, Top-1={no_ctx_res['top1_hit_rate']*100:.1f}%")

    # 2.2 w/o Feature Gate
    print("[*] Evaluating VulnGNN w/o Feature Gate...")
    no_gate_res, _ = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, encoder="sage", use_feature_gate=False, epochs=25, seed=42)
    results["architectural_ablations"]["w/o Feature Gate"] = no_gate_res
    print(f"    -> w/o Gate: F1={no_gate_res['f1']:.4f}, PR-AUC={no_gate_res['pr_auc']:.4f}, MRR={no_gate_res['mrr']:.4f}, Top-1={no_gate_res['top1_hit_rate']*100:.1f}%")

    # 2.3 GAT (4-Head Graph Attention)
    print("[*] Evaluating VulnGNN w/ GAT (4-Head Attention)...")
    gat_res, _ = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, encoder="gat", heads=4, epochs=25, seed=42)
    results["architectural_ablations"]["GAT (4-Head)"] = gat_res
    print(f"    -> GAT:      F1={gat_res['f1']:.4f}, PR-AUC={gat_res['pr_auc']:.4f}, MRR={gat_res['mrr']:.4f}, Top-1={gat_res['top1_hit_rate']*100:.1f}%")

    # =========================================================================
    # 3. FEATURE-GROUP ABLATIONS
    # =========================================================================
    print("\n" + "=" * 80)
    print("  [3/4] FEATURE-GROUP ABLATIONS (Leave-One-Out & Group-Only)")
    print("=" * 80)

    # 3.1 Leave-one-group-out
    print("[*] Running Leave-One-Group-Out Ablations...")
    all_indices = set(range(len(FEATURE_NAMES)))
    for gname, gidxs in FEATURE_GROUPS.items():
        rem_idxs = sorted(list(all_indices - set(gidxs)))
        ab_res, _ = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, encoder="sage", feature_mask=rem_idxs, epochs=20, seed=42)
        results["feature_group_ablations"]["leave_one_group_out"][f"w/o_{gname}"] = ab_res
        print(f"    -> w/o {gname:12s} ({len(rem_idxs)} feats): F1={ab_res['f1']:.4f}, PR-AUC={ab_res['pr_auc']:.4f}, MRR={ab_res['mrr']:.4f}, Top-1={ab_res['top1_hit_rate']*100:.1f}%")

    # 3.2 Group-only evaluations
    print("\n[*] Running Group-Only Ablations...")
    for gname, gidxs in FEATURE_GROUPS.items():
        ab_res, _ = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, encoder="sage", feature_mask=gidxs, epochs=20, seed=42)
        results["feature_group_ablations"]["group_only"][f"{gname}_only"] = ab_res
        print(f"    -> {gname:12s} ONLY ({len(gidxs)} feats): F1={ab_res['f1']:.4f}, PR-AUC={ab_res['pr_auc']:.4f}, MRR={ab_res['mrr']:.4f}, Top-1={ab_res['top1_hit_rate']*100:.1f}%")

    # =========================================================================
    # 4. MULTI-CORPUS GENERALIZATION EVALUATION
    # =========================================================================
    print("\n" + "=" * 80)
    print("  [4/4] HELD-OUT SUBSET & REAL-WORLD BINARY GENERALIZATION")
    print("=" * 80)

    # 4.1 Evaluate VulnGNN on Juliet test set specifically
    print("[*] Evaluating trained VulnGNN on Juliet Held-Out Test Set (403 graphs)...")
    ju_targets = [d.y.cpu().numpy() for d in ju_te]
    ju_probs = []
    ju_preds = []
    vulngnn_model.eval()
    dev = next(vulngnn_model.parameters()).device
    with torch.no_grad():
        for d in ju_te:
            logits = vulngnn_model(d.x.to(dev), d.edge_index.to(dev)) / vulngnn_res["temperature"]
            p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            ju_probs.append(p)
            ju_preds.append((p >= vulngnn_res["optimal_threshold"]).astype(np.int64))
    ju_eval = evaluate_graph_ranking(ju_targets, ju_probs, ju_preds)
    results["corpus_breakdown"]["juliet_heldout_test"] = ju_eval
    print(f"    -> Juliet Test:   F1={ju_eval['f1']:.4f}, PR-AUC={ju_eval['pr_auc']:.4f}, ROC-AUC={ju_eval['roc_auc']:.4f}, MRR={ju_eval['mrr']:.4f}, Top-1={ju_eval['top1_hit_rate']*100:.1f}%, FPR={ju_eval['clean_binary_fpr']*100:.1f}%")

    # 4.2 Evaluate VulnGNN on PrimeVul real-world CVE test set specifically
    print("[*] Evaluating trained VulnGNN on PrimeVul Real-CVE Test Set (372 graphs)...")
    pv_targets = [d.y.cpu().numpy() for d in pv_te]
    pv_probs = []
    pv_preds = []
    with torch.no_grad():
        for d in pv_te:
            logits = vulngnn_model(d.x.to(dev), d.edge_index.to(dev)) / vulngnn_res["temperature"]
            p = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            pv_probs.append(p)
            pv_preds.append((p >= vulngnn_res["optimal_threshold"]).astype(np.int64))
    pv_eval = evaluate_graph_ranking(pv_targets, pv_probs, pv_preds)
    results["corpus_breakdown"]["primevul_heldout_test"] = pv_eval
    print(f"    -> PrimeVul Test: F1={pv_eval['f1']:.4f}, PR-AUC={pv_eval['pr_auc']:.4f}, ROC-AUC={pv_eval['roc_auc']:.4f}, MRR={pv_eval['mrr']:.4f}, Top-1={pv_eval['top1_hit_rate']*100:.1f}%, FPR={pv_eval['clean_binary_fpr']*100:.1f}%")

    # 4.3 Evaluate Real-World Stripped System Binaries
    print(f"[*] Evaluating on {len(list(Path(real_dir).glob('*.pt')))} Real-World Stripped System Binaries...")
    real_pts = sorted(p for p in Path(real_dir).glob("*.pt") if not p.name.startswith("._"))
    real_stats = []
    total_nodes = 0
    total_flagged = 0
    with torch.no_grad():
        for p in real_pts:
            g = torch.load(p, weights_only=False)
            logits = vulngnn_model(g.x.to(dev), g.edge_index.to(dev)) / vulngnn_res["temperature"]
            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            flagged = int((probs >= vulngnn_res["optimal_threshold"]).sum())
            n = int(g.num_nodes)
            total_nodes += n
            total_flagged += flagged
            pruned_pct = (1.0 - (flagged / max(n, 1))) * 100.0
            real_stats.append({
                "binary": getattr(g, "binary_name", p.stem),
                "nodes": n,
                "edges": int(g.num_edges),
                "flagged_candidates": flagged,
                "pruned_pct": round(pruned_pct, 2),
            })
    overall_pruned = (1.0 - (total_flagged / max(total_nodes, 1))) * 100.0
    results["corpus_breakdown"]["real_world_system_binaries"] = {
        "binaries_evaluated": len(real_stats),
        "total_nodes": total_nodes,
        "total_flagged_candidates": total_flagged,
        "overall_pruned_pct": round(overall_pruned, 2),
        "sample_binaries": real_stats[:10],
    }
    print(f"    -> Real-World Binaries: Total Nodes={total_nodes}, Flagged Candidates={total_flagged}, Pruned={overall_pruned:.2f}%")

    # =========================================================================
    # SAVE STRUCTURED ARTIFACTS
    # =========================================================================
    out_file = os.path.join(ROOT_DIR, "benchmark_baselines_ablations.json")
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Saved detailed baseline & ablation results to: {out_file}")

    # Merge key fields into benchmark_gnn_results.json
    gnn_results_file = os.path.join(ROOT_DIR, "benchmark_gnn_results.json")
    if os.path.exists(gnn_results_file):
        with open(gnn_results_file) as f:
            legacy_data = json.load(f)
        legacy_data["baseline_comparison"] = results["baselines"]
        legacy_data["architectural_ablations"] = results["architectural_ablations"]
        legacy_data["feature_group_ablations_detailed"] = results["feature_group_ablations"]
        legacy_data["ranking_lifts"] = results["ranking_lifts"]
        with open(gnn_results_file, "w") as f:
            json.dump(legacy_data, f, indent=2)
        print(f"[+] Updated {gnn_results_file} with baseline and ablation tables.")

    print("=" * 80)
    print("  PHASE 3 BASELINE & ABLATION EXPERIMENTS COMPLETED SUCCESSFULLY!")
    print("=" * 80)


if __name__ == "__main__":
    main()
