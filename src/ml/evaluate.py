#!/usr/bin/env python3
"""
Evaluation Script for GNN Vulnerability Detector
=================================================

Provides research-grade evaluation metrics:
- Per-CWE precision, recall, F1, ROC-AUC
- Per-binary analysis
- Comparison vs heuristic baselines
- Statistical significance tests
- Ablation study support
"""

import os
import sys
import json
import argparse
from pathlib import Path
from collections import defaultdict

# Add project to path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

try:
    import torch
    import torch.nn.functional as F
    import numpy as np
    from torch_geometric.loader import DataLoader
    from sklearn.metrics import (
        precision_recall_fscore_support,
        roc_auc_score,
        average_precision_score,
        confusion_matrix,
        classification_report
    )
    from scipy import stats
except ImportError as e:
    print(f"[-] Missing dependencies: {e}")
    print("Install: pip install torch torch-geometric scikit-learn scipy")
    sys.exit(1)

from src.ml.gnn_model import VulnGNN, create_model, VulnGNNEnsemble
from src.graph.feature_extractor import FEATURE_NAMES


def load_model_and_data(model_path, dataset_dir, temperature_path=None, threshold_path=None):
    """Load model and dataset."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Load model
    checkpoint = torch.load(model_path, map_location=device)
    config = checkpoint.get('config', {
        'input_dim': len(FEATURE_NAMES),
        'hidden_dim': 128,
        'num_layers': 3,
        'encoder': 'sage',
        'dropout': 0.3
    })
    
    model = create_model(**config).to(device)
    model.load_state_dict(checkpoint['model_state_dict'])
    model.eval()
    
    # Load temperature
    temperature = 1.0
    if temperature_path and os.path.exists(temperature_path):
        with open(temperature_path) as f:
            temperature = json.load(f).get('temperature', 1.0)
    elif os.path.exists(model_path.replace('.pt', '_temperature.json')):
        with open(model_path.replace('.pt', '_temperature.json')) as f:
            temperature = json.load(f).get('temperature', 1.0)
    
    model.set_temperature(temperature)
    
    # Load threshold
    threshold = 0.5
    if threshold_path and os.path.exists(threshold_path):
        with open(threshold_path) as f:
            threshold = json.load(f).get('threshold', 0.5)
    elif os.path.exists(model_path.replace('.pt', '_threshold.json')):
        with open(model_path.replace('.pt', '_threshold.json')) as f:
            threshold = json.load(f).get('threshold', 0.5)
    
    # Load dataset
    dataset = []
    for file_path in Path(dataset_dir).glob("*.pt"):
        try:
            data = torch.load(file_path, weights_only=False)
            data.binary_name = file_path.stem
            # Extract CWE from filename
            cwe = None
            for part in file_path.stem.split('_'):
                if part.startswith('CWE') and part[3:].isdigit():
                    cwe = part
                    break
            data.cwe = cwe
            if hasattr(data, 'y') and data.y is not None:
                dataset.append(data)
        except Exception as e:
            print(f"[-] Error loading {file_path}: {e}")
    
    return model, dataset, device, temperature, threshold


def evaluate_per_cwe(model, dataset, device, temperature, threshold):
    """Compute metrics per CWE category."""
    cwe_results = defaultdict(lambda: {
        'targets': [], 'probs': [], 'preds': [],
        'binaries': set()
    })
    
    all_targets = []
    all_probs = []
    all_preds = []
    
    loader = DataLoader(dataset, batch_size=8, shuffle=False)
    
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            out = model(batch.x, batch.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
            targets = batch.y.cpu().numpy()
            preds = (probs > threshold).astype(int)
            
            # Aggregate by CWE
            for i in range(batch.num_graphs):
                mask = batch.batch == i
                if not mask.any():
                    continue
                    
                # Find the binary/CWE for this graph
                idx = mask.nonzero(as_tuple=True)[0][0].item()
                # Get the original data index
                data_idx = batch.idx[i].item() if hasattr(batch, 'idx') else i
                
                # We need to map back to the dataset
                # For simplicity, use the batch order
                pass
    
    # Alternative: evaluate each graph individually for CWE attribution
    for data in dataset:
        cwe = data.cwe or 'UNKNOWN'
        data = data.to(device)
        
        out = model(data.x, data.edge_index)
        out = out / temperature
        probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
        targets = data.y.cpu().numpy()
        preds = (probs > threshold).astype(int)
        
        cwe_results[cwe]['targets'].extend(targets)
        cwe_results[cwe]['probs'].extend(probs)
        cwe_results[cwe]['preds'].extend(preds)
        cwe_results[cwe]['binaries'].add(data.binary_name)
        
        all_targets.extend(targets)
        all_probs.extend(probs)
        all_preds.extend(preds)
    
    return cwe_results, all_targets, all_probs, all_preds


def compute_metrics(targets, probs, preds):
    """Compute all metrics for a set of predictions."""
    if len(targets) == 0:
        return {}
    
    targets = np.array(targets)
    probs = np.array(probs)
    preds = np.array(preds)
    
    metrics = {}
    
    try:
        precision, recall, f1, _ = precision_recall_fscore_support(
            targets, preds, average='binary', zero_division=0
        )
        metrics['precision'] = float(precision)
        metrics['recall'] = float(recall)
        metrics['f1'] = float(f1)
    except:
        metrics['precision'] = metrics['recall'] = metrics['f1'] = 0.0
    
    try:
        metrics['roc_auc'] = float(roc_auc_score(targets, probs))
    except:
        metrics['roc_auc'] = 0.0
    
    try:
        metrics['avg_precision'] = float(average_precision_score(targets, probs))
    except:
        metrics['avg_precision'] = 0.0
    
    cm = confusion_matrix(targets, preds)
    metrics['confusion_matrix'] = cm.tolist()
    metrics['tn'] = int(cm[0, 0]) if cm.shape == (2, 2) else 0
    metrics['fp'] = int(cm[0, 1]) if cm.shape == (2, 2) else 0
    metrics['fn'] = int(cm[1, 0]) if cm.shape == (2, 2) else 0
    metrics['tp'] = int(cm[1, 1]) if cm.shape == (2, 2) else 0
    
    metrics['num_samples'] = len(targets)
    metrics['num_positive'] = int(targets.sum())
    metrics['positive_rate'] = float(targets.mean())
    
    return metrics


def print_cwe_table(cwe_results):
    """Print formatted CWE metrics table."""
    print("\n" + "=" * 100)
    print(f"{'CWE':<12} {'Binaries':>8} {'Nodes':>8} {'Vuln%':>7} {'Prec':>7} {'Rec':>7} {'F1':>7} {'ROC-AUC':>8} {'AP':>7}")
    print("-" * 100)
    
    for cwe in sorted(cwe_results.keys()):
        r = cwe_results[cwe]
        if len(r['targets']) == 0:
            continue
        
        m = compute_metrics(r['targets'], r['probs'], r['preds'])
        
        print(f"{cwe:<12} {len(r['binaries']):>8} {m['num_samples']:>8} "
              f"{m['positive_rate']*100:>6.1f}% "
              f"{m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} "
              f"{m['roc_auc']:>7.3f} {m['avg_precision']:>6.3f}")
    
    # Overall
    all_targets = []
    all_probs = []
    all_preds = []
    for r in cwe_results.values():
        all_targets.extend(r['targets'])
        all_probs.extend(r['probs'])
        all_preds.extend(r['preds'])
    
    if all_targets:
        m = compute_metrics(all_targets, all_probs, all_preds)
        print("-" * 100)
        print(f"{'OVERALL':<12} {sum(len(r['binaries']) for r in cwe_results.values()):>8} "
              f"{m['num_samples']:>8} {m['positive_rate']*100:>6.1f}% "
              f"{m['precision']:>6.3f} {m['recall']:>6.3f} {m['f1']:>6.3f} "
              f"{m['roc_auc']:>7.3f} {m['avg_precision']:>6.3f}")
    print("=" * 100)


def compare_with_baseline(model, dataset, device, temperature, threshold):
    """Compare GNN with simple heuristic baselines."""
    print("\n[+] Comparing with heuristic baselines...")
    
    # Baseline 1: High-degree nodes (nodes with many connections)
    # Baseline 2: Blocks with memory writes
    # Baseline 3: Loop headers
    # Baseline 4: Library calls
    
    baseline_results = {}
    
    # GNN predictions
    gnn_probs = []
    gnn_preds = []
    all_targets = []
    
    for data in dataset:
        data = data.to(device)
