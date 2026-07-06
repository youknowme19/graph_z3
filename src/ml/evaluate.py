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
        out = model(data.x, data.edge_index)
        out = out / temperature
        probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
        gnn_probs.extend(probs)
        gnn_preds.extend((probs > threshold).astype(int))
        all_targets.extend(data.y.cpu().numpy())
    
    gnn_metrics = compute_metrics(all_targets, gnn_probs, gnn_preds)
    baseline_results['GNN'] = gnn_metrics
    
    # Heuristic 1: High structural centrality (in_deg * out_deg)
    # Feature 7 in our 40-dim vector is flow_centrality
    print("  Computing heuristic baselines...")
    
    # Heuristic: threshold on feature 7 (flow_centrality)
    for feat_idx, feat_name in [
        (7, 'flow_centrality'),
        (25, 'has_memory_write'),
        (3, 'is_loop_header'),
        (14, 'is_library_call'),
        (17, 'has_unsafe_string'),
        (18, 'has_format_string'),
        (26, 'num_symbolic_variables'),
    ]:
        if feat_idx < 40:
            probs = []
            targets = []
            for data in dataset:
                targets.extend(data.y.cpu().numpy())
                probs.extend(data.x[:, feat_idx].cpu().numpy())
            
            if len(set(targets)) > 1:
                # Find best threshold for this feature
                best_f1 = 0
                best_thresh = 0
                probs_arr = np.array(probs)
                targets_arr = np.array(targets)
                
                for thresh in np.linspace(probs_arr.min(), probs_arr.max(), 50):
                    preds = (probs_arr > thresh).astype(int)
                    _, _, f1, _ = precision_recall_fscore_support(
                        targets_arr, preds, average='binary', zero_division=0
                    )
                    if f1 > best_f1:
                        best_f1 = f1
                        best_thresh = thresh
                
                preds = (probs_arr > best_thresh).astype(int)
                metrics = compute_metrics(targets_arr, probs_arr, preds)
                baseline_results[f'Heuristic_{feat_name}'] = metrics
    
    # Print comparison
    print("\n" + "=" * 90)
    print(f"{'Method':<25} {'Precision':>9} {'Recall':>9} {'F1':>9} {'ROC-AUC':>9} {'AP':>9}")
    print("-" * 90)
    for name, m in baseline_results.items():
        print(f"{name:<25} {m['precision']:>8.3f} {m['recall']:>8.3f} {m['f1']:>8.3f} "
              f"{m['roc_auc']:>8.3f} {m['avg_precision']:>8.3f}")
    print("=" * 90)
    
    return baseline_results


def statistical_significance(model, dataset, device, temperature, threshold, n_bootstrap=1000):
    """Bootstrap confidence intervals for metrics."""
    print(f"\n[+] Computing bootstrap confidence intervals (n={n_bootstrap})...")
    
    # Collect all predictions
    all_data = []
    for data in dataset:
        data = data.to(device)
        out = model(data.x, data.edge_index)
        out = out / temperature
        probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
        targets = data.y.cpu().numpy()
        preds = (probs > threshold).astype(int)
        all_data.append((targets, probs, preds))
    
    # Bootstrap
    f1_scores = []
    roc_aucs = []
    precisions = []
    recalls = []
    
    n_samples = sum(len(d[0]) for d in all_data)
    
    for _ in range(n_bootstrap):
        # Sample with replacement at the graph level
        boot_data = np.random.choice(all_data, size=len(all_data), replace=True)
        
        boot_targets = np.concatenate([d[0] for d in boot_data])
        boot_probs = np.concatenate([d[1] for d in boot_data])
        boot_preds = np.concatenate([d[2] for d in boot_data])
        
        try:
            _, _, f1, _ = precision_recall_fscore_support(
                boot_targets, boot_preds, average='binary', zero_division=0
            )
            roc_auc = roc_auc_score(boot_targets, boot_probs)
            
            f1_scores.append(f1)
            roc_aucs.append(roc_auc)
            precisions.append(precision_recall_fscore_support(
                boot_targets, boot_preds, average='binary', zero_division=0
            )[0])
            recalls.append(precision_recall_fscore_support(
                boot_targets, boot_preds, average='binary', zero_division=0
            )[1])
        except:
            continue
    
    def ci(values):
        if not values:
            return (0, 0)
        return (np.percentile(values, 2.5), np.percentile(values, 97.5))
    
    print(f"\nBootstrap 95% Confidence Intervals:")
    print(f"  F1:          {np.mean(f1_scores):.4f} [{ci(f1_scores)[0]:.4f}, {ci(f1_scores)[1]:.4f}]")
    print(f"  ROC-AUC:     {np.mean(roc_aucs):.4f} [{ci(roc_aucs)[0]:.4f}, {ci(roc_aucs)[1]:.4f}]")
    print(f"  Precision:   {np.mean(precisions):.4f} [{ci(precisions)[0]:.4f}, {ci(precisions)[1]:.4f}]")
    print(f"  Recall:      {np.mean(recalls):.4f} [{ci(recalls)[0]:.4f}, {ci(recalls)[1]:.4f}]")


def ablation_study(model, dataset, device, temperature, threshold):
    """Ablation: evaluate impact of each feature group."""
    print("\n[+] Running ablation study...")
    
    # Feature groups from feature_extractor.py
    feature_groups = {
        'structural': list(range(0, 8)),
        'instruction': list(range(8, 14)),
        'semantic': list(range(14, 26)),
        'dataflow': list(range(26, 34)),
        'symbolic': list(range(34, 40)),
    }
    
    # Full model
    all_targets = []
    all_probs = []
    for data in dataset:
        data = data.to(device)
        out = model(data.x, data.edge_index)
        out = out / temperature
        probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
        all_probs.extend(probs)
        all_targets.extend(data.y.cpu().numpy())
    
    full_preds = (np.array(all_probs) > threshold).astype(int)
    full_metrics = compute_metrics(all_targets, all_probs, full_preds)
    print(f"  Full model (40 features): F1={full_metrics['f1']:.4f}, AUC={full_metrics['roc_auc']:.4f}")
    
    # Ablate each group
    print("  Note: Full ablation requires model retraining without feature groups.")
    print("  For true ablation, retrain with masked feature groups.")
    print("  Current approach: zero out feature groups at inference (approximate)")
    
    # Approximate ablation by zeroing features
    for group_name, indices in feature_groups.items():
        probs_list = []
        targets_list = []
        for data in dataset:
            # Create copy with zeroed features
            x = data.x.clone()
            x[:, indices] = 0.0
            data_mod = data.clone()
            data_mod.x = x
            data_mod = data_mod.to(device)
            
            out = model(data_mod.x, data_mod.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)[:, 1].cpu().numpy()
            probs_list.extend(probs)
            targets_list.extend(data.y.cpu().numpy())
        
        preds = (np.array(probs_list) > threshold).astype(int)
        metrics = compute_metrics(targets_list, probs_list, preds)
        drop_f1 = full_metrics['f1'] - metrics['f1']
        drop_auc = full_metrics['roc_auc'] - metrics['roc_auc']
        print(f"  Without {group_name:12s}: F1={metrics['f1']:.4f} (Δ={drop_f1:+.4f}), "
              f"AUC={metrics['roc_auc']:.4f} (Δ={drop_auc:+.4f})")


def main():
    parser = argparse.ArgumentParser(description="Evaluate GNN vulnerability detector")
    parser.add_argument("--model-path", type=str, required=True, help="Path to trained model (.pt)")
    parser.add_argument("--dataset-dir", type=str, required=True, help="Directory containing .pt graphs")
    parser.add_argument("--temperature-path", type=str, help="Path to temperature file")
    parser.add_argument("--threshold-path", type=str, help="Path to threshold file")
    parser.add_argument("--output", type=str, help="Output JSON file for results")
    parser.add_argument("--compare-baseline", action="store_true", help="Compare with heuristic baselines")
    parser.add_argument("--bootstrap", action="store_true", help="Compute bootstrap confidence intervals")
    parser.add_argument("--ablation", action="store_true", help="Run ablation study")
    parser.add_argument("--per-cwe", action="store_true", help="Show per-CWE metrics")
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("GNN Vulnerability Detector - Research Evaluation")
    print("=" * 60)
    
    # Load model and data
    model, dataset, device, temperature, threshold = load_model_and_data(
        args.model_path, args.dataset_dir, args.temperature_path, args.threshold_path
    )
    
    print(f"[+] Loaded model from {args.model_path}")
    print(f"[+] Loaded {len(dataset)} graphs from dataset")
    print(f"[+] Temperature: {temperature:.3f}")
    print(f"[+] Threshold: {threshold:.3f}")
    print(f"[+] Device: {device}")
    
    # Evaluate per CWE
    cwe_results, all_targets, all_probs, all_preds = evaluate_per_cwe(
        model, dataset, device, temperature, threshold
    )
    
    if args.per_cwe:
        print_cwe_table(cwe_results)
    
    # Overall metrics
    overall = compute_metrics(all_targets, all_probs, all_preds)
    print("\n[+] Overall Metrics:")
    for k, v in overall.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")
        elif isinstance(v, int):
            print(f"  {k}: {v}")
        else:
            print(f"  {k}: {v}")
    
    # Compare with baselines
    if args.compare_baseline:
        compare_with_baseline(model, dataset, device, temperature, threshold)
    
    # Bootstrap confidence intervals
    if args.bootstrap:
        statistical_significance(model, dataset, device, temperature, threshold)
    
    # Ablation study
    if args.ablation:
        ablation_study(model, dataset, device, temperature, threshold)
    
    # Save results
    if args.output:
        results = {
            'overall': overall,
            'per_cwe': {},
            'config': {
                'model_path': args.model_path,
                'dataset_dir': args.dataset_dir,
                'temperature': temperature,
                'threshold': threshold,
                'num_graphs': len(dataset)
            }
        }
        
        for cwe, r in cwe_results.items():
            if r['targets']:
                results['per_cwe'][cwe] = compute_metrics(r['targets'], r['probs'], r['preds'])
                results['per_cwe'][cwe]['num_binaries'] = len(r['binaries'])
        
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")
    
    print("\n[+] Evaluation complete!")


if __name__ == "__main__":
    main()