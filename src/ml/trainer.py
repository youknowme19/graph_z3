import os
import sys
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
    import torch.optim as optim
    from torch_geometric.loader import DataLoader
    from torch_geometric.data import Batch
    from sklearn.metrics import (
        classification_report, 
        precision_recall_fscore_support,
        roc_auc_score,
        average_precision_score,
        confusion_matrix
    )
    import numpy as np
except ImportError:
    torch = None

from src.ml.gnn_model import VulnGNN, create_model
from src.graph.feature_extractor import FEATURE_NAMES


def _get_binary_name_from_graph(data):
    """Extract binary name from graph data (stored in node_addrs or similar)."""
    # Try various ways to get the binary identifier
    if hasattr(data, 'binary_name'):
        return data.binary_name
    if hasattr(data, 'file_name'):
        return data.file_name
    # Fallback: use a hash of the graph structure
    return f"graph_{hash(str(data.edge_index.tolist())) % 10000}"


def _split_by_binary(dataset, train_ratio=0.7, val_ratio=0.15, test_ratio=0.15, seed=42):
    """
    Split dataset by binary to prevent data leakage.
    Graphs from the same binary must stay in the same split.
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6
    
    # Group graphs by binary
    binary_to_graphs = defaultdict(list)
    for data in dataset:
        binary_name = _get_binary_name_from_graph(data)
        binary_to_graphs[binary_name].append(data)
    
    binary_names = list(binary_to_graphs.keys())
    random.seed(seed)
    random.shuffle(binary_names)
    
    n_train = int(train_ratio * len(binary_names))
    n_val = int(val_ratio * len(binary_names))
    
    train_binaries = set(binary_names[:n_train])
    val_binaries = set(binary_names[n_train:n_train + n_val])
    test_binaries = set(binary_names[n_train + n_val:])
    
    train_data = []
    val_data = []
    test_data = []
    
    for binary_name, graphs in binary_to_graphs.items():
        if binary_name in train_binaries:
            train_data.extend(graphs)
        elif binary_name in val_binaries:
            val_data.extend(graphs)
        else:
            test_data.extend(graphs)
    
    return train_data, val_data, test_data


def _compute_class_weights(dataset, device):
    """Compute class weights from dataset."""
    all_y = torch.cat([data.y for data in dataset])
    num_safe = (all_y == 0).sum().item()
    num_vuln = (all_y == 1).sum().item()
    print(f"[+] Class distribution: Safe={num_safe}, Vulnerable={num_vuln}")
    
    if num_vuln == 0:
        weight = torch.tensor([1.0, 1.0], device=device)
    else:
        weight = torch.tensor([1.0, float(num_safe) / (num_vuln + 1e-6)], device=device)
    
    print(f"[+] Loss class weights: Safe={weight[0].item():.2f}, Vulnerable={weight[1].item():.2f}")
    return weight


def _evaluate_model(model, loader, criterion, device, temperature=None):
    """Evaluate model on a data loader."""
    model.eval()
    total_loss = 0
    all_preds = []
    all_targets = []
    all_probs = []
    all_logits = []
    per_graph_metrics = []
    
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index)
            
            # Apply temperature scaling if provided
            if temperature is not None:
                out = out / temperature
            
            loss = criterion(out, batch.y)
            total_loss += loss.item() * batch.num_graphs
            
            probs = torch.softmax(out, dim=1)
            preds = probs.argmax(dim=1)
            
            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(batch.y.cpu().numpy())
            all_probs.extend(probs[:, 1].cpu().numpy())  # P(vulnerable)
            all_logits.extend(out.cpu().numpy())
            
            # Per-graph metrics
            for i in range(batch.num_graphs):
                mask = batch.batch == i
                if mask.sum() > 0:
                    g_preds = preds[mask].cpu().numpy()
                    g_targets = batch.y[mask].cpu().numpy()
                    g_probs = probs[mask, 1].cpu().numpy()
                    
                    # Only compute if there are both classes
                    if len(set(g_targets)) > 1:
                        try:
                            auc = roc_auc_score(g_targets, g_probs)
                            ap = average_precision_score(g_targets, g_probs)
                        except:
                            auc = 0.0
                            ap = 0.0
                    else:
                        auc = 0.0
                        ap = 0.0
                    
                    per_graph_metrics.append({
                        'num_nodes': int(mask.sum()),
                        'num_vuln': int(g_targets.sum()),
                        'auc': auc,
                        'ap': ap,
                        'accuracy': float((g_preds == g_targets).mean())
                    })
    
    avg_loss = total_loss / len(loader.dataset)
    
    # Overall metrics
    precision, recall, f1, _ = precision_recall_fscore_support(
        all_targets, all_preds, average='binary', zero_division=0
    )
    
    try:
        roc_auc = roc_auc_score(all_targets, all_probs)
    except:
        roc_auc = 0.0
    
    try:
        avg_prec = average_precision_score(all_targets, all_probs)
    except:
        avg_prec = 0.0
    
    cm = confusion_matrix(all_targets, all_preds)
    
    return {
        'loss': avg_loss,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'roc_auc': roc_auc,
        'avg_precision': avg_prec,
        'confusion_matrix': cm.tolist(),
        'per_graph': per_graph_metrics,
        'predictions': all_preds,
        'targets': all_targets,
        'probabilities': all_probs,
        'logits': all_logits
    }


def _find_optimal_temperature(model, val_loader, device, temp_range=(0.5, 5.0), n_iter=50):
    """Find optimal temperature for calibration on validation set."""
    model.eval()
    
    # Collect logits and targets
    all_logits = []
    all_targets = []
    
    with torch.no_grad():
        for batch in val_loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index)
            all_logits.append(out.cpu())
            all_targets.append(batch.y.cpu())
    
    all_logits = torch.cat(all_logits, dim=0)
    all_targets = torch.cat(all_targets, dim=0)
    
    # Grid search for temperature
    best_temp = 1.0
    best_nll = float('inf')
    
    temps = np.linspace(temp_range[0], temp_range[1], n_iter)
    for temp in temps:
        scaled_logits = all_logits / temp
        probs = torch.softmax(scaled_logits, dim=1)
        # Negative log likelihood
        nll = -torch.log(probs[torch.arange(len(all_targets)), all_targets] + 1e-8).mean().item()
        if nll < best_nll:
            best_nll = nll
            best_temp = temp
    
    print(f"[+] Optimal temperature: {best_temp:.3f} (NLL: {best_nll:.4f})")
    return best_temp


def _find_optimal_threshold(model, val_loader, device, temperature=1.0):
    """
    Find optimal classification threshold on validation set.
    Optimizes for F1 score (harmonic mean of precision and recall).
    """
    model.eval()
    
    all_probs = []
    all_targets = []
    
    with torch.no_grad():
        for batch in val_loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)
            all_probs.append(probs[:, 1].cpu())
            all_targets.append(batch.y.cpu())
    
    all_probs = torch.cat(all_probs, dim=0).numpy()
    all_targets = torch.cat(all_targets, dim=0).numpy()
    
    # Grid search for threshold
    best_thresh = 0.5
    best_f1 = 0.0
    
    # Try thresholds from 0.1 to 0.9
    thresholds = np.linspace(0.1, 0.9, 81)
    for thresh in thresholds:
        preds = (all_probs > thresh).astype(int)
        precision, recall, f1, _ = precision_recall_fscore_support(
            all_targets, preds, average='binary', zero_division=0
        )
        if f1 > best_f1:
            best_f1 = f1
            best_thresh = thresh
    
    print(f"[+] Optimal threshold: {best_thresh:.3f} (F1: {best_f1:.4f})")
    return float(best_thresh)


def train_model(
    dataset_dir,
    epochs=100,
    lr=0.001,
    model_path="model.pt",
    hidden_dim=128,
    num_layers=3,
    encoder='sage',
    dropout=0.3,
    batch_size=8,
    patience=15,
    weight_decay=1e-4,
    seed=42,
    use_cross_validation=False,
    n_folds=5
):
    if torch is None:
        raise ImportError("PyTorch, PyTorch Geometric, and Scikit-learn must be installed to run training.")
    
    # Set seeds for reproducibility
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
    
    # 1. Load the dataset
    dataset = []
    dataset_dir = Path(dataset_dir)
    
    if not dataset_dir.exists():
        print(f"[-] Dataset directory {dataset_dir} does not exist.")
        return
    
    pt_files = list(dataset_dir.glob("*.pt"))
    print(f"[+] Found {len(pt_files)} .pt files")
    
    for file_path in pt_files:
        try:
            data = torch.load(file_path, weights_only=False)
            # Store binary name
            data.binary_name = file_path.stem
