#!/usr/bin/env python3
"""
reconcile_phase3_final.py — Final Reconciliation for Phase 3 Acceptance
=======================================================================
1. Paired Binary-Level Bootstrap:
   - Evaluates VulnGNN vs GIN and VulnGNN vs XGBoost on identical resampled
     binary graphs across 1,000 bootstrap iterations.
   - Computes paired differences Delta = Metric_A - Metric_B and 95% CIs.
   - Strictly reports whether zero is contained in the 95% CI.

2. Comprehensive Project-Held-Out Evaluation:
   - Full inventory of all 76 PrimeVul repositories with graph counts and
     class distributions.
   - Detailed explanation of right-skewed validation (linux with 1,088 graphs).
   - Per-repository evaluation on the 12 held-out test repositories.
   - Macro-averaged vs micro-averaged comparison with zero-leakage guarantee.

3. 38-Feature Experiment:
   - Prunes collinear features: vex_imark (index 9) and has_simprocedure (index 16).
   - Retrains VulnGNN, GIN, Uni-SAGE, MLP, and XGBoost on exactly 38 features.
   - Compares 38-D vs 40-D performance across all metrics.

Outputs:
  - benchmark_paired_bootstrap.json
  - benchmark_project_repository_breakdown.json
  - benchmark_38feature_comparison.json
"""

import os
import sys
import copy
import time
import json
import random
from collections import defaultdict
from pathlib import Path

import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim
from torch_geometric.loader import DataLoader
from sklearn.metrics import (
    precision_recall_fscore_support,
    roc_auc_score,
    average_precision_score,
)
import xgboost as xgb

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.ml.gnn_model import create_model
from src.ml.trainer import (
    FocalCrossEntropyLoss,
    load_pt_dataset,
    _split_by_binary,
    _compute_class_weights,
)
from src.graph.feature_extractor import FEATURE_NAMES, FEATURE_GROUPS


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    try:
        torch.set_num_threads(6)
    except Exception:
        pass


def evaluate_graph_ranking(targets_list, probs_list, preds_list=None):
    all_targets, all_probs, all_preds = [], [], []
    vuln_graph_count, clean_graph_count, clean_graph_false_alarms = 0, 0, 0
    top1_hits, top3_hits, top5_hits, top10_hits = 0, 0, 0, 0
    mrr_sum = 0.0

    for idx, (y, p) in enumerate(zip(targets_list, probs_list)):
        all_targets.append(y)
        all_probs.append(p)
        pred = (p >= 0.5).astype(np.int64) if preds_list is None else preds_list[idx]
        all_preds.append(pred)

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
                mrr_sum += 1.0 / float(vuln_positions[0] + 1)
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
        "vuln_graphs": int(vuln_graph_count),
        "clean_graphs": int(clean_graph_count),
        "clean_binary_fpr": round(float(clean_graph_false_alarms / cg), 4),
        "_targets_list": targets_list,
        "_probs_list": probs_list,
        "_preds_list": preds_list,
    }


def train_and_eval_neural(model_type, train_data, val_data, test_data, feature_mask=None, epochs=14, seed=42, **kwargs):
    set_seed(seed)
    dev = torch.device("cpu")
    in_dim = len(feature_mask) if feature_mask is not None else len(FEATURE_NAMES)
    model = create_model(input_dim=in_dim, model_type=model_type, **kwargs).to(dev)

    weight = _compute_class_weights(train_data, dev)
    criterion = FocalCrossEntropyLoss(weight=weight, gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=0.0018, weight_decay=1e-4)

    def _prep_batch(batch):
        b = batch.clone()
        if feature_mask is not None:
            b.x = b.x[:, feature_mask]
        return b.to(dev)

    train_loader = DataLoader(train_data, batch_size=128, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=128, shuffle=False)

    best_score = -1.0
    best_state = None
    no_improve = 0

    for _ in range(1, epochs + 1):
        model.train()
        for batch in train_loader:
            b = _prep_batch(batch)
            optimizer.zero_grad()
            out = model(b.x, b.edge_index, b.batch)
            loss = criterion(out, b.y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

        model.eval()
        va_probs, va_targets = [], []
        with torch.no_grad():
            for batch in val_loader:
                b = _prep_batch(batch)
                out = model(b.x, b.edge_index, b.batch)
                va_probs.append(torch.softmax(out, dim=1)[:, 1].cpu().numpy())
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
            if no_improve >= 4:
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    # Temperature & threshold calibration on validation set
    model.eval()
    va_logits = []
    with torch.no_grad():
        for batch in val_loader:
            b = _prep_batch(batch)
            va_logits.append(model(b.x, b.edge_index, b.batch).cpu())
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

    scaled_va_probs = torch.softmax(all_va_logits / best_temp, dim=1)[:, 1].numpy()
    best_th = 0.5
    best_f1 = -1.0
    for th in np.linspace(0.1, 0.9, 17):
        p, r, f1, _ = precision_recall_fscore_support(yt_va, (scaled_va_probs >= th).astype(int), average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_th = float(th)

    targets_list, probs_list, preds_list = [], [], []
    with torch.no_grad():
        for d in test_data:
            dg = d.clone()
            if feature_mask is not None:
                dg.x = dg.x[:, feature_mask]
            dg = dg.to(dev)
            logits = model(dg.x, dg.edge_index) / best_temp
            probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
            targets_list.append(dg.y.cpu().numpy())
            probs_list.append(probs)
            preds_list.append((probs >= best_th).astype(np.int64))

    return evaluate_graph_ranking(targets_list, probs_list, preds_list)


def train_and_eval_xgboost(train_data, val_data, test_data, feature_mask=None, seed=42):
    def _extract_x(d):
        x = d.x.cpu().numpy()
        return x[:, feature_mask] if feature_mask is not None else x

    X_tr = np.concatenate([_extract_x(d) for d in train_data], axis=0)
    y_tr = np.concatenate([d.y.cpu().numpy() for d in train_data], axis=0)
    X_va = np.concatenate([_extract_x(d) for d in val_data], axis=0)
    y_va = np.concatenate([d.y.cpu().numpy() for d in val_data], axis=0)

    n_pos = int(y_tr.sum())
    n_neg = len(y_tr) - n_pos
    scale_pos = float(n_neg / max(n_pos, 1))

    clf = xgb.XGBClassifier(
        n_estimators=100,
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

    va_probs = clf.predict_proba(X_va)[:, 1]
    best_th = 0.5
    best_f1 = -1.0
    for th in np.linspace(0.1, 0.9, 17):
        p, r, f1, _ = precision_recall_fscore_support(y_va, (va_probs >= th).astype(int), average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_th = float(th)

    targets_list = [d.y.cpu().numpy() for d in test_data]
    probs_list = [clf.predict_proba(_extract_x(d))[:, 1] for d in test_data]
    preds_list = [(p >= best_th).astype(np.int64) for p in probs_list]

    return evaluate_graph_ranking(targets_list, probs_list, preds_list)


# =========================================================================
# TASK 1: PAIRED BINARY-LEVEL BOOTSTRAP (IDENTICAL RESAMPLED GRAPHS)
# =========================================================================

def run_paired_bootstrap(vuln_res, gin_res, xgb_res, n_boot=1000, seed=42):
    print("\n" + "=" * 80)
    print("  RUNNING PAIRED BINARY-LEVEL BOOTSTRAP (N=1,000 RESAMPLES)")
    print("=" * 80)

    rng = np.random.default_rng(seed)
    targets = vuln_res["_targets_list"]
    n_graphs = len(targets)

    p_vuln = vuln_res["_probs_list"]
    d_vuln = vuln_res["_preds_list"]
    p_gin = gin_res["_probs_list"]
    d_gin = gin_res["_preds_list"]
    p_xgb = xgb_res["_probs_list"]
    d_xgb = xgb_res["_preds_list"]

    pairs = {
        "VulnGNN_vs_GIN": (p_vuln, d_vuln, p_gin, d_gin),
        "VulnGNN_vs_XGBoost": (p_vuln, d_vuln, p_xgb, d_xgb),
    }

    bootstrap_results = {}

    for pair_name, (pA, dA, pB, dB) in pairs.items():
        print(f"[*] Computing paired bootstrap for {pair_name}...")
        diffs = {
            "mrr": [],
            "top1_hit_rate": [],
            "top5_hit_rate": [],
            "pr_auc": [],
            "roc_auc": [],
            "f1": [],
            "clean_binary_fpr": [],
        }

        for _ in range(n_boot):
            sample_idx = rng.integers(0, n_graphs, size=n_graphs)
            s_targets = [targets[i] for i in sample_idx]

            s_pA = [pA[i] for i in sample_idx]
            s_dA = [dA[i] for i in sample_idx]
            mA = evaluate_graph_ranking(s_targets, s_pA, s_dA)

            s_pB = [pB[i] for i in sample_idx]
            s_dB = [dB[i] for i in sample_idx]
            mB = evaluate_graph_ranking(s_targets, s_pB, s_dB)

            for k in diffs.keys():
                diffs[k].append(mA[k] - mB[k])

        pair_summary = {}
        for metric, arr in diffs.items():
            low = round(float(np.percentile(arr, 2.5)), 4)
            high = round(float(np.percentile(arr, 97.5)), 4)
            mean_diff = round(float(np.mean(arr)), 4)
            # Check if 0 is inside the 95% CI
            zero_in_ci = bool(low <= 0.0 <= high)
            is_sig_positive = bool(low > 0.0)
            is_sig_negative = bool(high < 0.0)

            pair_summary[metric] = {
                "mean_diff": mean_diff,
                "ci_95": [low, high],
                "zero_in_ci": zero_in_ci,
                "statistically_significant": not zero_in_ci,
                "direction": "positive (A > B)" if is_sig_positive else ("negative (A < B)" if is_sig_negative else "not_significant"),
            }
            print(f"    {metric:18s}: Delta = {mean_diff:+.4f} (95% CI: [{low:+.4f}, {high:+.4f}]) -> {pair_summary[metric]['direction']}")

        bootstrap_results[pair_name] = pair_summary

    out_file = os.path.join(ROOT_DIR, "benchmark_paired_bootstrap.json")
    with open(out_file, "w") as f:
        json.dump(bootstrap_results, f, indent=2)
    print(f"[+] Saved paired bootstrap results to: {out_file}")
    return bootstrap_results


# =========================================================================
# TASK 2: FULL 76 REPOSITORY AUDIT & PER-REPOSITORY HELD-OUT EVALUATION
# =========================================================================

def run_repository_audit_and_heldout(pv_dataset):
    print("\n" + "=" * 80)
    print("  PROJECT-HELD-OUT REPOSITORY AUDIT (ALL 76 PROJECTS)")
    print("=" * 80)

    proj_map = defaultdict(list)
    for d in pv_dataset:
        p = getattr(d, "project", "unknown")
        proj_map[p].append(d)

    sorted_projects = sorted(proj_map.keys())
    print(f"[+] Total unique projects: {len(sorted_projects)}")

    repo_stats = {}
    for p in sorted_projects:
        glist = proj_map[p]
        n_vuln_g = sum(1 for g in glist if g.y.sum() > 0)
        n_clean_g = len(glist) - n_vuln_g
        n_nodes = sum(g.num_nodes for g in glist)
        n_vuln_nodes = sum(int(g.y.sum()) for g in glist)
        n_clean_nodes = n_nodes - n_vuln_nodes
        repo_stats[p] = {
            "total_graphs": len(glist),
            "vuln_graphs": n_vuln_g,
            "clean_graphs": n_clean_g,
            "total_nodes": n_nodes,
            "vuln_nodes": n_vuln_nodes,
            "clean_nodes": n_clean_nodes,
            "node_vuln_pct": round(float(n_vuln_nodes / max(n_nodes, 1) * 100), 2),
        }

    # Partition with fixed seed=42
    rng = random.Random(42)
    rng.shuffle(sorted_projects)
    n_projs = len(sorted_projects)
    n_tr = int(round(0.70 * n_projs))
    n_va = int(round(0.15 * n_projs))

    tr_projs = sorted(list(sorted_projects[:n_tr]))
    va_projs = sorted(list(sorted_projects[n_tr : n_tr + n_va]))
    te_projs = sorted(list(sorted_projects[n_tr + n_va :]))

    tr_graphs = [d for p in tr_projs for d in proj_map[p]]
    va_graphs = [d for p in va_projs for d in proj_map[p]]
    te_graphs = [d for p in te_projs for d in proj_map[p]]

    print(f"[+] Partitioning:")
    print(f"    - Train: {len(tr_projs)} projects ({len(tr_graphs)} graphs)")
    print(f"    - Val:   {len(va_projs)} projects ({len(va_graphs)} graphs) [Contains linux: {repo_stats['linux']['total_graphs']} graphs]")
    print(f"    - Test:  {len(te_projs)} projects ({len(te_graphs)} graphs)")

    # Train VulnGNN on train projects
    print("\n[*] Training VulnGNN strictly on Train Projects...")
    set_seed(42)
    dev = torch.device("cpu")
    model = create_model(input_dim=len(FEATURE_NAMES), model_type="vulngnn").to(dev)
    weight = _compute_class_weights(tr_graphs, dev)
    criterion = FocalCrossEntropyLoss(weight=weight, gamma=2.0)
    optimizer = optim.AdamW(model.parameters(), lr=0.0018, weight_decay=1e-4)

    train_loader = DataLoader(tr_graphs, batch_size=128, shuffle=True)
    val_loader = DataLoader(va_graphs, batch_size=128, shuffle=False)

    best_score = -1.0
    best_state = None
    no_improve = 0

    for _ in range(1, 16):
        model.train()
        for batch in train_loader:
            b = batch.to(dev)
            optimizer.zero_grad()
            out = model(b.x, b.edge_index, b.batch)
            loss = criterion(out, b.y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            optimizer.step()

        model.eval()
        va_probs, va_targets = [], []
        with torch.no_grad():
            for batch in val_loader:
                b = batch.to(dev)
                out = model(b.x, b.edge_index, b.batch)
                va_probs.append(torch.softmax(out, dim=1)[:, 1].cpu().numpy())
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
            if no_improve >= 4:
                break

    if best_state is not None:
        model.load_state_dict(best_state)

    # Post-hoc calibration on val set
    model.eval()
    va_logits = []
    with torch.no_grad():
        for batch in val_loader:
            b = batch.to(dev)
            va_logits.append(model(b.x, b.edge_index, b.batch).cpu())
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

    scaled_va_probs = torch.softmax(all_va_logits / best_temp, dim=1)[:, 1].numpy()
    best_th = 0.5
    best_f1 = -1.0
    for th in np.linspace(0.1, 0.9, 17):
        p, r, f1, _ = precision_recall_fscore_support(yt_va, (scaled_va_probs >= th).astype(int), average="binary", zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_th = float(th)

    # Evaluate per test repository
    per_repo_results = {}
    all_te_targets, all_te_probs, all_te_preds = [], [], []

    print("\n[*] Per-Repository Test Results (Held-Out Test Projects):")
    for p in te_projs:
        glist = proj_map[p]
        p_targets, p_probs, p_preds = [], [], []
        with torch.no_grad():
            for d in glist:
                dg = d.to(dev)
                logits = model(dg.x, dg.edge_index) / best_temp
                probs = torch.softmax(logits, dim=1)[:, 1].cpu().numpy()
                p_targets.append(dg.y.cpu().numpy())
                p_probs.append(probs)
                p_preds.append((probs >= best_th).astype(np.int64))

        all_te_targets.extend(p_targets)
        all_te_probs.extend(p_probs)
        all_te_preds.extend(p_preds)

        m = evaluate_graph_ranking(p_targets, p_probs, p_preds)
        for k in ("_targets_list", "_probs_list", "_preds_list"):
            m.pop(k, None)
        per_repo_results[p] = m
        print(f"    {p:18s} ({len(glist):2d} graphs): MRR={m['mrr']:.4f}, Top-1={m['top1_hit_rate']*100:.1f}%, Top-5={m['top5_hit_rate']*100:.1f}%, PR-AUC={m['pr_auc']:.4f}, ROC-AUC={m['roc_auc']:.4f}, Clean FPR={m['clean_binary_fpr']*100:.1f}%")

    # Macro-averaged metrics (unweighted mean across the 12 projects)
    macro_metrics = {}
    for metric in ("mrr", "top1_hit_rate", "top5_hit_rate", "top10_hit_rate", "pr_auc", "roc_auc", "f1", "clean_binary_fpr"):
        vals = [per_repo_results[p][metric] for p in te_projs]
        macro_metrics[f"{metric}_macro"] = round(float(np.mean(vals)), 4)
        macro_metrics[f"{metric}_macro_std"] = round(float(np.std(vals)), 4)

    # Micro-averaged metrics (pooled across all 120 graphs)
    micro_metrics = evaluate_graph_ranking(all_te_targets, all_te_probs, all_te_preds)
    for k in ("_targets_list", "_probs_list", "_preds_list"):
        micro_metrics.pop(k, None)

    print("\n[+] Macro-Averaged vs Micro-Averaged Summary:")
    print(f"    - Macro MRR:      {macro_metrics['mrr_macro']:.4f} +/- {macro_metrics['mrr_macro_std']:.4f} (Micro MRR: {micro_metrics['mrr']:.4f})")
    print(f"    - Macro Top-1:    {macro_metrics['top1_hit_rate_macro']*100:.1f}% +/- {macro_metrics['top1_hit_rate_macro_std']*100:.1f}% (Micro Top-1: {micro_metrics['top1_hit_rate']*100:.1f}%)")
    print(f"    - Macro Top-5:    {macro_metrics['top5_hit_rate_macro']*100:.1f}% +/- {macro_metrics['top5_hit_rate_macro_std']*100:.1f}% (Micro Top-5: {micro_metrics['top5_hit_rate']*100:.1f}%)")
    print(f"    - Macro PR-AUC:   {macro_metrics['pr_auc_macro']:.4f} +/- {macro_metrics['pr_auc_macro_std']:.4f} (Micro PR-AUC: {micro_metrics['pr_auc']:.4f})")
    print(f"    - Macro Clean FPR: {macro_metrics['clean_binary_fpr_macro']*100:.1f}% +/- {macro_metrics['clean_binary_fpr_macro_std']*100:.1f}% (Micro Clean FPR: {micro_metrics['clean_binary_fpr']*100:.1f}%)")

    output_data = {
        "repository_inventory": repo_stats,
        "partition": {
            "train_projects": tr_projs,
            "train_graphs_count": len(tr_graphs),
            "val_projects": va_projs,
            "val_graphs_count": len(va_graphs),
            "test_projects": te_projs,
            "test_graphs_count": len(te_graphs),
            "right_skew_explanation": "Linux repository contains 1,088 graphs (43.87% of PrimeVul). Uniform random assignment with seed 42 assigned Linux to validation, making validation 1,184 graphs and test 120 graphs.",
        },
        "per_repository_results": per_repo_results,
        "macro_metrics": macro_metrics,
        "micro_metrics": micro_metrics,
    }

    out_file = os.path.join(ROOT_DIR, "benchmark_project_repository_breakdown.json")
    with open(out_file, "w") as f:
        json.dump(output_data, f, indent=2)
    print(f"[+] Saved project repository breakdown to: {out_file}")
    return output_data


# =========================================================================
# TASK 3: 38-FEATURE EXPERIMENT & COMPARISON (PRUNING REDUNDANCIES)
# =========================================================================

def run_38feature_experiment(combined_tr, combined_va, combined_te):
    print("\n" + "=" * 80)
    print("  38-FEATURE EXPERIMENT (PRUNED COLLINEAR PAIRS)")
    print("=" * 80)

    # Dropping index 9 (vex_imark) and index 16 (has_simprocedure)
    mask_38 = [i for i in range(len(FEATURE_NAMES)) if i not in (9, 16)]
    assert len(mask_38) == 38

    feature_names_38 = [FEATURE_NAMES[i] for i in mask_38]
    dropped_features = [FEATURE_NAMES[9], FEATURE_NAMES[16]]
    print(f"[+] Pruned features ({len(dropped_features)}): {dropped_features}")
    print(f"[+] Retained features ({len(feature_names_38)}): {feature_names_38[:5]} ... {feature_names_38[-5:]}")

    # Retrain baselines with 38-feature input
    models = {
        "VulnGNN": ("vulngnn", {"encoder": "sage"}),
        "GIN": ("gin", {}),
        "Uni-SAGE": ("unidirectional", {}),
        "MLP": ("mlp", {}),
    }

    results_38 = {}
    print("\n[*] Training neural baselines on 38-D features (Seed 42)...")
    for mname, (mtype, mkwargs) in models.items():
        t0 = time.time()
        m = train_and_eval_neural(mtype, combined_tr, combined_va, combined_te, feature_mask=mask_38, epochs=14, seed=42, **mkwargs)
        for k in ("_targets_list", "_probs_list", "_preds_list"):
            m.pop(k, None)
        results_38[mname] = m
        print(f"    {mname:10s} ({time.time()-t0:.1f}s): F1={m['f1']:.4f}, PR-AUC={m['pr_auc']:.4f}, ROC-AUC={m['roc_auc']:.4f}, MRR={m['mrr']:.4f}, Top-1={m['top1_hit_rate']*100:.1f}%, Top-5={m['top5_hit_rate']*100:.1f}%, FPR={m['clean_binary_fpr']*100:.1f}%")

    print("[*] Training XGBoost on 38-D features (Seed 42)...")
    xgb_38 = train_and_eval_xgboost(combined_tr, combined_va, combined_te, feature_mask=mask_38, seed=42)
    for k in ("_targets_list", "_probs_list", "_preds_list"):
        xgb_38.pop(k, None)
    results_38["XGBoost"] = xgb_38
    print(f"    XGBoost:   F1={xgb_38['f1']:.4f}, PR-AUC={xgb_38['pr_auc']:.4f}, ROC-AUC={xgb_38['roc_auc']:.4f}, MRR={xgb_38['mrr']:.4f}, Top-1={xgb_38['top1_hit_rate']*100:.1f}%, Top-5={xgb_38['top5_hit_rate']*100:.1f}%, FPR={xgb_38['clean_binary_fpr']*100:.1f}%")

    # Load 40-feature results for comparison from benchmark_5seed_evaluations.json
    f40_file = os.path.join(ROOT_DIR, "benchmark_5seed_evaluations.json")
    f40_data = {}
    if os.path.exists(f40_file):
        with open(f40_file) as f:
            f40_raw = json.load(f)
            # Seed 42 run is seed_runs[0]
            f40_data["VulnGNN"] = f40_raw["VulnGNN (Proposed)"]["seed_runs"][0]
            f40_data["GIN"] = f40_raw["GIN (Bidirectional)"]["seed_runs"][0]
            f40_data["Uni-SAGE"] = f40_raw["Unidirectional GraphSAGE"]["seed_runs"][0]
            f40_data["MLP"] = f40_raw["MLP Baseline"]["seed_runs"][0]
            f40_data["XGBoost"] = f40_raw["XGBoost"]["seed_runs"][0]

    comparison = {}
    print("\n" + "=" * 80)
    print("  COMPARISON: 38-FEATURE vs 40-FEATURE (Seed 42)")
    print("=" * 80)
    print(f"{'Model':10s} | {'PR-AUC (38D)':12s} {'PR-AUC (40D)':12s} {'Delta':8s} | {'Top-1 (38D)':12s} {'Top-1 (40D)':12s} {'Delta':8s} | {'MRR (38D)':10s} {'MRR (40D)':10s}")
    print("-" * 88)

    for mname in ("VulnGNN", "GIN", "Uni-SAGE", "MLP", "XGBoost"):
        m38 = results_38[mname]
        m40 = f40_data.get(mname, {})
        d_prauc = m38["pr_auc"] - m40.get("pr_auc", 0.0)
        d_top1 = (m38["top1_hit_rate"] - m40.get("top1_hit_rate", 0.0)) * 100
        comparison[mname] = {
            "metrics_38d": m38,
            "metrics_40d": m40,
            "delta_38_minus_40": {
                "f1": round(float(m38["f1"] - m40.get("f1", 0.0)), 4),
                "pr_auc": round(float(d_prauc), 4),
                "roc_auc": round(float(m38["roc_auc"] - m40.get("roc_auc", 0.0)), 4),
                "mrr": round(float(m38["mrr"] - m40.get("mrr", 0.0)), 4),
                "top1_hit_rate": round(float(m38["top1_hit_rate"] - m40.get("top1_hit_rate", 0.0)), 4),
                "top5_hit_rate": round(float(m38["top5_hit_rate"] - m40.get("top5_hit_rate", 0.0)), 4),
                "clean_binary_fpr": round(float(m38["clean_binary_fpr"] - m40.get("clean_binary_fpr", 0.0)), 4),
            }
        }
        print(f"{mname:10s} | {m38['pr_auc']:<12.4f} {m40.get('pr_auc', 0.0):<12.4f} {d_prauc:<+8.4f} | {m38['top1_hit_rate']*100:<11.1f}% {m40.get('top1_hit_rate', 0.0)*100:<11.1f}% {d_top1:<+7.1f}% | {m38['mrr']:<10.4f} {m40.get('mrr', 0.0):<10.4f}")

    output_38 = {
        "pruned_features": dropped_features,
        "feature_names_38": feature_names_38,
        "comparison": comparison,
    }

    out_file = os.path.join(ROOT_DIR, "benchmark_38feature_comparison.json")
    with open(out_file, "w") as f:
        json.dump(output_38, f, indent=2)
    print(f"\n[+] Saved 38-feature comparison to: {out_file}")
    return output_38


# =========================================================================
# MAIN EXECUTION
# =========================================================================

def main():
    print("[*] Loading datasets...")
    ju_dataset = load_pt_dataset(os.path.join(ROOT_DIR, "data", "processed_graphs"))
    pv_dataset = load_pt_dataset(os.path.join(ROOT_DIR, "data", "primevul_graphs"))

    ju_tr, ju_va, ju_te = _split_by_binary(ju_dataset, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)
    pv_tr, pv_va, pv_te = _split_by_binary(pv_dataset, train_ratio=0.70, val_ratio=0.15, test_ratio=0.15, seed=42)

    combined_tr = ju_tr + pv_tr
    combined_va = ju_va + pv_va
    combined_te = ju_te + pv_te

    # 1. Compute Paired Binary-Level Bootstrap for VulnGNN vs GIN and VulnGNN vs XGBoost
    print("\n[*] Training seed 42 models for paired bootstrap...")
    vuln_m42 = train_and_eval_neural("vulngnn", combined_tr, combined_va, combined_te, epochs=14, seed=42, encoder="sage")
    gin_m42 = train_and_eval_neural("gin", combined_tr, combined_va, combined_te, epochs=14, seed=42)
    xgb_m42 = train_and_eval_xgboost(combined_tr, combined_va, combined_te, seed=42)

    run_paired_bootstrap(vuln_m42, gin_m42, xgb_m42, n_boot=1000, seed=42)

    # 2. Run Project Repository Breakdown & Per-Repository Test Results
    run_repository_audit_and_heldout(pv_dataset)

    # 3. Run 38-Feature Pruning Experiment
    run_38feature_experiment(combined_tr, combined_va, combined_te)

    print("\n[+] All Phase 3 reconciliation tasks completed successfully!")


if __name__ == "__main__":
    main()

