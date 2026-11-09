import os
import sys
import re
import math
import argparse
import json
import random
from collections import defaultdict
from pathlib import Path

# Ensure we can import from src and core
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
    from torch_geometric.loader import DataLoader
    from sklearn.metrics import (
        classification_report,
        precision_recall_fscore_support,
        roc_auc_score,
        average_precision_score,
        confusion_matrix,
    )
    import numpy as np
except ImportError:
    torch = None

from src.ml.gnn_model import VulnGNN, create_model
from src.graph.feature_extractor import FEATURE_NAMES


class FocalCrossEntropyLoss(nn.Module if torch is not None else object):
    """Class-weighted Focal Cross-Entropy Loss for severe basic-block class imbalance (~1:200)."""
    def __init__(self, weight=None, gamma: float = 2.0):
        super().__init__()
        self.weight = weight
        self.gamma = gamma

    def forward(self, logits, targets):
        ce_loss = F.cross_entropy(logits, targets, weight=self.weight, reduction="none")
        probs = F.softmax(logits, dim=1)
        pt = probs.gather(1, targets.unsqueeze(1)).squeeze(1).clamp(min=1e-7, max=1.0)
        focal_term = (1.0 - pt) ** self.gamma
        return (focal_term * ce_loss).mean()


def _get_group_key(data) -> str:
    """Group key by base testcase stem so optimization/patched twins never cross Train/Val/Test."""
    if hasattr(data, "base_testcase") and data.base_testcase:
        return str(data.base_testcase)
    bname = getattr(data, "binary_name", "") or getattr(data, "file_name", "")
    if bname:
        stem = bname.replace(".out", "").replace(".pt", "")
        stem = re.sub(r"(_PATCHED)?_(O0|O1|O2|O3|Os)$", "", stem)
        return stem
    return f"graph_{hash(str(data.edge_index.tolist())) % 100000}"


def _extract_cwe(data) -> str:
    if hasattr(data, "cwe") and data.cwe:
        return str(data.cwe)
    bname = getattr(data, "binary_name", "") or ""
    for part in bname.split("_"):
        if part.startswith("CWE") and part[3:].isdigit():
            return part
    return "UNKNOWN"


def _split_by_binary(dataset, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42):
    """
    Stratified group split by (CWE, base_testcase) to prevent any data leakage
    while guaranteeing balanced CWE representation across Train / Val / Test.
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6
    rng = random.Random(seed)

    cwe_to_groups = defaultdict(lambda: defaultdict(list))
    for data in dataset:
        src_tag = getattr(data, "corpus_source", "bin") or "bin"
        cwe = f"{src_tag}::{_extract_cwe(data)}"
        gkey = _get_group_key(data)
        cwe_to_groups[cwe][gkey].append(data)

    train_data, val_data, test_data = [], [], []
    for cwe, group_dict in sorted(cwe_to_groups.items()):
        gkeys = sorted(group_dict.keys())
        rng.shuffle(gkeys)
        n = len(gkeys)
        n_train = max(1, int(round(train_ratio * n)))
        n_val = max(1, int(round(val_ratio * n))) if n >= 4 else 0
        if test_ratio > 0 and n_train + n_val >= n and n >= 3:
            n_train = n - 2
            n_val = 1

        for g in gkeys[:n_train]:
            train_data.extend(group_dict[g])
        for g in gkeys[n_train : n_train + n_val]:
            val_data.extend(group_dict[g])
        for g in gkeys[n_train + n_val :]:
            test_data.extend(group_dict[g])

    return train_data, val_data, test_data


def _compute_class_weights(dataset, device):
    """Compute tempered class weights suitable for Focal Cross-Entropy."""
    all_y = torch.cat([data.y for data in dataset])
    num_safe = int((all_y == 0).sum().item())
    num_vuln = int((all_y == 1).sum().item())
    print(f"[+] Class distribution: Safe={num_safe:,}, Vulnerable={num_vuln:,}")

    if num_vuln == 0:
        weight = torch.tensor([1.0, 1.0], device=device)
    else:
        raw_ratio = float(num_safe) / float(num_vuln)
        # Tempered weight (dampened linear/sqrt blend) avoids massive false-positive inflation
        pos_weight = min(35.0, max(4.0, math.sqrt(raw_ratio) * 1.8))
        weight = torch.tensor([1.0, pos_weight], device=device)

    print(f"[+] Focal class weights: Safe={weight[0].item():.2f}, Vulnerable={weight[1].item():.2f}")
    return weight


def _evaluate_model(model, loader, criterion, device, temperature=None, threshold=0.5):
    """Evaluate model on node-level metrics and per-binary Top-K ranking hit rates."""
    model.eval()
    total_loss = 0.0
    all_preds = []
    all_targets = []
    all_probs = []
    per_graph_metrics = []

    top1_hits = 0
    top3_hits = 0
    top5_hits = 0
    top10_hits = 0
    mrr_sum = 0.0
    vuln_graph_count = 0
    clean_graph_count = 0
    clean_graph_false_alarms = 0

    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch)
            if temperature is not None:
                out = out / temperature

            loss = criterion(out, batch.y)
            total_loss += float(loss.item()) * batch.num_graphs

            probs = torch.softmax(out, dim=1)
            vuln_p = probs[:, 1]
            preds = (vuln_p >= threshold).long()

            all_preds.append(preds.cpu().numpy())
            all_targets.append(batch.y.cpu().numpy())
            all_probs.append(vuln_p.cpu().numpy())

            for i in range(batch.num_graphs):
                mask = batch.batch == i
                if mask.sum() == 0:
                    continue
                g_preds = preds[mask].cpu().numpy()
                g_targets = batch.y[mask].cpu().numpy()
                g_probs = vuln_p[mask].cpu().numpy()
                n_vuln = int(g_targets.sum())

                if n_vuln > 0:
                    vuln_graph_count += 1
                    ranked_idx = np.argsort(-g_probs)
                    if g_targets[ranked_idx[:1]].sum() > 0:
                        top1_hits += 1
                    if g_targets[ranked_idx[:3]].sum() > 0:
                        top3_hits += 1
                    if g_targets[ranked_idx[:5]].sum() > 0:
                        top5_hits += 1
                    if g_targets[ranked_idx[:10]].sum() > 0:
                        top10_hits += 1
                    vuln_ranks = np.where(g_targets[ranked_idx] == 1)[0]
                    if len(vuln_ranks) > 0:
                        mrr_sum += 1.0 / float(vuln_ranks[0] + 1)
                    try:
                        auc = float(roc_auc_score(g_targets, g_probs))
                        ap = float(average_precision_score(g_targets, g_probs))
                    except Exception:
                        auc, ap = 0.0, 0.0
                else:
                    clean_graph_count += 1
                    if int(g_preds.sum()) > 0:
                        clean_graph_false_alarms += 1
                    auc, ap = 0.0, 0.0

                per_graph_metrics.append({
                    "num_nodes": int(mask.sum().item()),
                    "num_vuln": n_vuln,
                    "auc": auc,
                    "ap": ap,
                    "accuracy": float((g_preds == g_targets).mean()),
                })

    all_preds_np = np.concatenate(all_preds) if all_preds else np.array([], dtype=np.int64)
    all_targets_np = np.concatenate(all_targets) if all_targets else np.array([], dtype=np.int64)
    all_probs_np = np.concatenate(all_probs) if all_probs else np.array([], dtype=np.float32)

    avg_loss = float(total_loss / max(len(loader.dataset), 1))
    precision, recall, f1, _ = precision_recall_fscore_support(
        all_targets_np, all_preds_np, average="binary", zero_division=0
    )

    try:
        roc_auc = float(roc_auc_score(all_targets_np, all_probs_np))
    except Exception:
        roc_auc = 0.0

    try:
        avg_prec = float(average_precision_score(all_targets_np, all_probs_np))
    except Exception:
        avg_prec = 0.0

    cm = confusion_matrix(all_targets_np, all_preds_np, labels=[0, 1])

    return {
        "loss": float(avg_loss),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
        "roc_auc": float(roc_auc),
        "avg_precision": float(avg_prec),
        "top1_hit_rate": float(top1_hits / max(vuln_graph_count, 1)),
        "top3_hit_rate": float(top3_hits / max(vuln_graph_count, 1)),
        "top5_hit_rate": float(top5_hits / max(vuln_graph_count, 1)),
        "top10_hit_rate": float(top10_hits / max(vuln_graph_count, 1)),
        "mrr": float(mrr_sum / max(vuln_graph_count, 1)),
        "vuln_graphs": int(vuln_graph_count),
        "clean_graphs": int(clean_graph_count),
        "clean_binary_fpr": float(clean_graph_false_alarms / max(clean_graph_count, 1)),
        "confusion_matrix": cm.tolist(),
        "per_graph": per_graph_metrics,
        "_raw_targets": all_targets_np,
        "_raw_preds": all_preds_np,
        "_raw_probs": all_probs_np,
    }


def _find_optimal_temperature(model, val_loader, device, temp_range=(0.5, 3.0), n_iter=40):
    """Find optimal temperature for probability calibration on validation set."""
    model.eval()
    all_logits = []
    all_targets = []

    with torch.no_grad():
        for batch in val_loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch)
            all_logits.append(out.cpu())
            all_targets.append(batch.y.cpu())

    all_logits = torch.cat(all_logits, dim=0)
    all_targets = torch.cat(all_targets, dim=0)

    best_temp = 1.0
    best_nll = float("inf")
    for temp in np.linspace(temp_range[0], temp_range[1], n_iter):
        scaled = all_logits / float(temp)
        probs = torch.softmax(scaled, dim=1)
        nll = -torch.log(probs[torch.arange(len(all_targets)), all_targets] + 1e-8).mean().item()
        if nll < best_nll:
            best_nll = nll
            best_temp = float(temp)

    print(f"[+] Optimal temperature: {best_temp:.3f} (NLL: {best_nll:.4f})")
    return float(best_temp)


def _find_optimal_threshold(model, val_loader, device, temperature=1.0):
    """Find optimal node classification threshold maximizing F1 on validation set."""
    model.eval()
    all_probs = []
    all_targets = []

    with torch.no_grad():
        for batch in val_loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index, batch.batch) / temperature
            probs = torch.softmax(out, dim=1)
            all_probs.append(probs[:, 1].cpu())
            all_targets.append(batch.y.cpu())

    all_probs = torch.cat(all_probs, dim=0).numpy()
    all_targets = torch.cat(all_targets, dim=0).numpy()

    best_thresh = 0.5
    best_f1 = 0.0
    for thresh in np.linspace(0.15, 0.95, 81):
        preds = (all_probs >= thresh).astype(int)
        _, _, f1, _ = precision_recall_fscore_support(
            all_targets, preds, average="binary", zero_division=0
        )
        if f1 > best_f1:
            best_f1 = float(f1)
            best_thresh = float(thresh)

    print(f"[+] Optimal threshold: {best_thresh:.3f} (Val F1: {best_f1:.4f})")
    return float(best_thresh)


def _select_device():
    if torch.cuda.is_available():
        return torch.device("cuda")
    # Note: PyG scatter ops on CPU are often very fast and 100% deterministic; test MPS fallback safely
    return torch.device("cpu")


def load_pt_dataset(dataset_dir):
    dataset = []
    if isinstance(dataset_dir, (list, tuple)):
        dirs = [Path(d) for d in dataset_dir]
    else:
        dirs = [Path(d.strip()) for d in str(dataset_dir).split(",") if d.strip()]

    for d_path in dirs:
        if not d_path.exists():
            continue
        pt_files = sorted(p for p in d_path.glob("*.pt") if not p.name.startswith("._"))
        print(f"[+] Found {len(pt_files)} .pt graph files in {d_path}")
        for file_path in pt_files:
            try:
                raw = torch.load(file_path, weights_only=False)
                if hasattr(raw, "y") and raw.y is not None and raw.x.shape[1] == len(FEATURE_NAMES):
                    from torch_geometric.data import Data
                    clean = Data(
                        x=raw.x.float(),
                        edge_index=raw.edge_index.long(),
                        y=raw.y.long(),
                    )
                    clean.binary_name = str(getattr(raw, "binary_name", "") or file_path.stem)
                    clean.cwe = str(getattr(raw, "cwe", "") or _extract_cwe(raw))
                    clean.cve = str(getattr(raw, "cve", "") or "")
                    clean.project = str(getattr(raw, "project", "") or "juliet")
                    clean.base_testcase = str(getattr(raw, "base_testcase", "") or _get_group_key(raw))
                    clean.opt_level = str(getattr(raw, "opt_level", "") or "O0")
                    clean.is_patched = bool(getattr(raw, "is_patched", False))
                    clean.corpus_source = str(
                        getattr(raw, "corpus_source", "")
                        or ("primevul_real_cve" if "primevul" in str(d_path) else "juliet_multi_cwe")
                    )
                    dataset.append(clean)
            except Exception as e:
                print(f"[-] Error loading {file_path.name}: {e}")
    return dataset


def train_model(
    dataset_dir,
    epochs=60,
    lr=0.0015,
    model_path="model.pt",
    hidden_dim=128,
    num_layers=3,
    encoder="sage",
    dropout=0.25,
    batch_size=32,
    patience=12,
    weight_decay=1e-4,
    seed=42,
):
    if torch is None:
        raise ImportError("PyTorch, PyTorch Geometric, and Scikit-learn must be installed.")

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)

    dataset = load_pt_dataset(dataset_dir)
    if not dataset:
        print("[-] No valid 40-dim graphs found in dataset directory.")
        return None, None

    total_blocks = sum(int(d.num_nodes) for d in dataset)
    total_edges = sum(int(d.num_edges) for d in dataset)
    distinct_cwes = sorted(set(_extract_cwe(d) for d in dataset))
    print(f"[+] Loaded {len(dataset):,} stripped binary graphs ({total_blocks:,} basic blocks, {total_edges:,} edges) across {len(distinct_cwes)} CWEs")

    train_data, val_data, test_data = _split_by_binary(dataset, seed=seed)
    print(f"[+] Stratified Group Split: Train={len(train_data):,}, Val={len(val_data):,}, Test={len(test_data):,}")

    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=batch_size, shuffle=False)

    device = _select_device()
    print(f"[+] Training on device: {device}")

    model = create_model(
        input_dim=len(FEATURE_NAMES),
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        encoder=encoder,
        dropout=dropout,
    ).to(device)

    weight = _compute_class_weights(train_data, device)
    criterion = FocalCrossEntropyLoss(weight=weight, gamma=2.0)

    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="max", factor=0.5, patience=4
    )

    best_score = -1.0
    best_val_loss = float("inf")
    best_epoch = 0
    epochs_no_improve = 0
    history = {
        "train_loss": [],
        "val_loss": [],
        "train_f1": [],
        "val_f1": [],
        "val_roc_auc": [],
        "val_avg_prec": [],
        "val_top1": [],
        "val_top5": [],
        "lr": [],
    }

    print(f"[+] Starting VulnGNN training for up to {epochs} epochs (batch_size={batch_size}, patience={patience})...")

    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0.0
        train_preds = []
        train_targets = []

        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            out = model(batch.x, batch.edge_index, batch.batch)
            loss = criterion(out, batch.y)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()

            total_loss += float(loss.item()) * batch.num_graphs
            preds = out.argmax(dim=1)
            train_preds.append(preds.cpu().numpy())
            train_targets.append(batch.y.cpu().numpy())

        avg_train_loss = total_loss / max(len(train_data), 1)
        tp_np = np.concatenate(train_preds)
        tt_np = np.concatenate(train_targets)
        _, _, train_f1, _ = precision_recall_fscore_support(tt_np, tp_np, average="binary", zero_division=0)

        val_metrics = _evaluate_model(model, val_loader, criterion, device)
        val_ap = val_metrics["avg_precision"]
        val_top5 = val_metrics["top5_hit_rate"]
        # Composite selection score prioritizing PR-AUC + Top-5 localization hit rate
        composite_val = 0.65 * val_ap + 0.35 * val_top5

        scheduler.step(composite_val)
        current_lr = float(optimizer.param_groups[0]["lr"])

        history["train_loss"].append(round(float(avg_train_loss), 5))
        history["val_loss"].append(round(float(val_metrics["loss"]), 5))
        history["train_f1"].append(round(float(train_f1), 5))
        history["val_f1"].append(round(float(val_metrics["f1"]), 5))
        history["val_roc_auc"].append(round(float(val_metrics["roc_auc"]), 5))
        history["val_avg_prec"].append(round(float(val_ap), 5))
        history["val_top1"].append(round(float(val_metrics["top1_hit_rate"]), 5))
        history["val_top5"].append(round(float(val_top5), 5))
        history["lr"].append(current_lr)

        if epoch == 1 or epoch % 3 == 0 or epoch == epochs:
            print(
                f"Epoch {epoch:03d}/{epochs:03d} | "
                f"Train Loss: {avg_train_loss:.4f} | Val Loss: {val_metrics['loss']:.4f} | "
                f"Val PR-AUC: {val_ap:.4f} | Val ROC-AUC: {val_metrics['roc_auc']:.4f} | "
                f"Val Top-1: {val_metrics['top1_hit_rate']*100:.1f}% | Val Top-5: {val_top5*100:.1f}% | "
                f"LR: {current_lr:.2e}",
                flush=True,
            )

        if composite_val > best_score:
            best_score = composite_val
            best_val_loss = float(val_metrics["loss"])
            best_epoch = epoch
            epochs_no_improve = 0
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": model.state_dict(),
                    "best_val_loss": best_val_loss,
                    "best_val_ap": float(val_ap),
                    "config": {
                        "input_dim": len(FEATURE_NAMES),
                        "hidden_dim": hidden_dim,
                        "num_layers": num_layers,
                        "encoder": encoder,
                        "dropout": dropout,
                    },
                    "history": history,
                    "feature_names": FEATURE_NAMES,
                    "split_counts": {
                        "total": len(dataset),
                        "train": len(train_data),
                        "val": len(val_data),
                        "test": len(test_data),
                    },
                },
                model_path,
            )
        else:
            epochs_no_improve += 1

        if epochs_no_improve >= patience:
            print(f"[+] Early stopping at epoch {epoch} (best epoch: {best_epoch})")
            break

    print(f"\n[+] Training completed. Best epoch: {best_epoch}, Best composite score: {best_score:.4f}")
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    model.load_state_dict(checkpoint["model_state_dict"])

    optimal_temp = _find_optimal_temperature(model, val_loader, device)
    model.set_temperature(optimal_temp)
    optimal_threshold = _find_optimal_threshold(model, val_loader, device, optimal_temp)

    # Persist calibrated temperature & threshold inside model.pt as well as sidecar JSONs
    checkpoint["model_state_dict"] = model.state_dict()
    checkpoint["temperature"] = optimal_temp
    checkpoint["threshold"] = optimal_threshold
    torch.save(checkpoint, model_path)

    temp_path = model_path.replace(".pt", "_temperature.json")
    with open(temp_path, "w") as f:
        json.dump({"temperature": optimal_temp}, f, indent=2)

    thresh_path = model_path.replace(".pt", "_threshold.json")
    with open(thresh_path, "w") as f:
        json.dump({"threshold": optimal_threshold}, f, indent=2)

    print("\n[+] Final evaluation on HELD-OUT TEST SET...")
    test_metrics = _evaluate_model(
        model, test_loader, criterion, device, temperature=optimal_temp, threshold=optimal_threshold
    )

    raw_targets = test_metrics.pop("_raw_targets")
    raw_preds = test_metrics.pop("_raw_preds")
    raw_probs = test_metrics.pop("_raw_probs")

    print(f"  Test Graphs:         {len(test_data)} ({test_metrics['vuln_graphs']} vuln + {test_metrics['clean_graphs']} clean)")
    print(f"  Node Precision:      {test_metrics['precision']*100:.2f}%")
    print(f"  Node Recall:         {test_metrics['recall']*100:.2f}%")
    print(f"  Node F1-Score:       {test_metrics['f1']:.4f}")
    print(f"  Node ROC-AUC:        {test_metrics['roc_auc']:.4f}")
    print(f"  Node PR-AUC (AP):    {test_metrics['avg_precision']:.4f}")
    print(f"  Top-1 Hit Rate:      {test_metrics['top1_hit_rate']*100:.2f}%")
    print(f"  Top-3 Hit Rate:      {test_metrics['top3_hit_rate']*100:.2f}%")
    print(f"  Top-5 Hit Rate:      {test_metrics['top5_hit_rate']*100:.2f}%")
    print(f"  Top-10 Hit Rate:     {test_metrics['top10_hit_rate']*100:.2f}%")
    print(f"  Clean Binary FPR:    {test_metrics['clean_binary_fpr']*100:.2f}%")
    print(f"  Confusion Matrix:\n{np.array(test_metrics['confusion_matrix'])}")

    results_path = model_path.replace(".pt", "_results.json")
    with open(results_path, "w") as f:
        json.dump(
            {
                "best_epoch": best_epoch,
                "best_val_loss": best_val_loss,
                "temperature": optimal_temp,
                "threshold": optimal_threshold,
                "split_counts": checkpoint["split_counts"],
                "test_metrics": {k: v for k, v in test_metrics.items() if k != "per_graph"},
                "history": history,
                "config": checkpoint["config"],
            },
            f,
            indent=2,
        )
    print(f"[+] Detailed results saved to {results_path}")

    if len(raw_targets) > 0:
        print("\n[+] Held-Out Test Set Node Classification Report:")
        print(
            classification_report(
                raw_targets,
                raw_preds,
                target_names=["Safe", "Vulnerable"],
                zero_division=0,
            )
        )

    return model, test_metrics


def evaluate_model(model_path, dataset_dir, temperature_path=None):
    if torch is None:
        raise ImportError("PyTorch required.")
    device = _select_device()
    checkpoint = torch.load(model_path, map_location=device, weights_only=False)
    config = checkpoint["config"]
    model = create_model(**config).to(device)
    model.load_state_dict(checkpoint["model_state_dict"])
    temp = checkpoint.get("temperature", 1.0)
    thresh = checkpoint.get("threshold", 0.5)
    if temperature_path and os.path.exists(temperature_path):
        with open(temperature_path) as f:
            temp = json.load(f)["temperature"]
    model.set_temperature(temp)

    dataset = load_pt_dataset(dataset_dir)
    loader = DataLoader(dataset, batch_size=32, shuffle=False)
    criterion = FocalCrossEntropyLoss()
    metrics = _evaluate_model(model, loader, criterion, device, temperature=temp, threshold=thresh)
    for k in ("_raw_targets", "_raw_preds", "_raw_probs"):
        metrics.pop(k, None)
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the VulnGNN vulnerability detector model.")
    parser.add_argument("--dataset-dir", type=str, required=True, help="Directory containing .pt graphs")
    parser.add_argument("--epochs", type=int, default=60, help="Number of training epochs")
    parser.add_argument("--lr", type=float, default=0.0015, help="Learning rate")
    parser.add_argument("--model-path", type=str, default="model.pt", help="Path to save the trained model (.pt)")
    parser.add_argument("--hidden-dim", type=int, default=128, help="Hidden dimension")
    parser.add_argument("--num-layers", type=int, default=3, help="Number of GNN layers")
    parser.add_argument("--encoder", type=str, default="sage", choices=["sage", "gat"], help="Encoder type")
    parser.add_argument("--dropout", type=float, default=0.25, help="Dropout rate")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--patience", type=int, default=12, help="Early stopping patience")
    parser.add_argument("--weight-decay", type=float, default=1e-4, help="Weight decay")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--eval-only", action="store_true", help="Only evaluate existing model")
    parser.add_argument("--temperature-path", type=str, help="Path to temperature file for eval")

    args = parser.parse_args()
    if args.eval_only:
        evaluate_model(args.model_path, args.dataset_dir, args.temperature_path)
    else:
        train_model(
            dataset_dir=args.dataset_dir,
            epochs=args.epochs,
            lr=args.lr,
            model_path=args.model_path,
            hidden_dim=args.hidden_dim,
            num_layers=args.num_layers,
            encoder=args.encoder,
            dropout=args.dropout,
            batch_size=args.batch_size,
            patience=args.patience,
            weight_decay=args.weight_decay,
            seed=args.seed,
        )
