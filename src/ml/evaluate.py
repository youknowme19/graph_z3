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

from src.ml.gnn_model import VulnGNN, create_model, VulnGNNEnsemble, load_checkpoint_model
from src.graph.feature_extractor import FEATURE_NAMES


def load_model_and_data(model_path, dataset_dir, temperature_path=None, threshold_path=None):
    """Load model and dataset."""
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Load model
    model = load_checkpoint_model(model_path, device=device)
    
    # Load temperature
    temperature = 1.0
    if temperature_path and os.path.exists(temperature_path):
        with open(temperature_path) as f:
            temperature = json.load(f).get('temperature', 1.0)
    elif os.path.exists(model_path.replace('.pt', '_temperature.json')):
        with open(model_path.replace('.pt', '_temperature.json')) as f:
            temperature = json.load(f).get('temperature', 1.0)
    
    if hasattr(model, 'set_temperature'):
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
    for file_path in sorted(Path(dataset_dir).glob("*.pt")):
        if file_path.name.startswith("._"):
            continue
        try:
            data = torch.load(file_path, weights_only=False)
            data.binary_name = file_path.stem.replace(".out", "")
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
    """Compute metrics per CWE category and per binary."""
    cwe_results = defaultdict(lambda: {
        'targets': [], 'probs': [], 'preds': [],
        'binaries': set()
    })
    binary_results = {}
    
    all_targets = []
    all_probs = []
    all_preds = []
    
    with torch.no_grad():
        for data in dataset:
            cwe = data.cwe or 'UNKNOWN'
            data = data.to(device)
            
            out = model(data.x, data.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)[:, 1].detach().cpu().numpy()
            targets = data.y.detach().cpu().numpy()
            preds = (probs > threshold).astype(int)
            
            cwe_results[cwe]['targets'].extend(targets)
            cwe_results[cwe]['probs'].extend(probs)
            cwe_results[cwe]['preds'].extend(preds)
            cwe_results[cwe]['binaries'].add(data.binary_name)
            
            all_targets.extend(targets)
            all_probs.extend(probs)
            all_preds.extend(preds)

            # Per binary ranking evaluation
            vuln_indices = np.where(targets == 1)[0]
            num_nodes = len(targets)
            num_edges = data.edge_index.shape[1] if hasattr(data, 'edge_index') else 0
            ranked_indices = np.argsort(-probs)
            
            top1_hit = False
            top5_hit = False
            top10_hit = False
            best_rank = None

            if len(vuln_indices) > 0:
                ranks = []
                for v_idx in vuln_indices:
                    rank = int(np.where(ranked_indices == v_idx)[0][0]) + 1
                    ranks.append(rank)
                best_rank = min(ranks)
                top1_hit = any(r <= 1 for r in ranks)
                top5_hit = any(r <= 5 for r in ranks)
                top10_hit = any(r <= 10 for r in ranks)
            
            m_bin = compute_metrics(targets, probs, preds)
            m_bin['num_nodes'] = num_nodes
            m_bin['num_edges'] = num_edges
            m_bin['num_vuln_nodes'] = int(targets.sum())
            m_bin['top1_hit'] = top1_hit
            m_bin['top5_hit'] = top5_hit
            m_bin['top10_hit'] = top10_hit
            m_bin['best_rank'] = best_rank
            m_bin['cwe'] = cwe
            binary_results[data.binary_name] = m_bin
    
    return cwe_results, binary_results, all_targets, all_probs, all_preds


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
    
    baseline_results = {}
    
    # GNN predictions
    gnn_probs = []
    gnn_preds = []
    all_targets = []
    
    with torch.no_grad():
        for data in dataset:
            data = data.to(device)
            out = model(data.x, data.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)[:, 1].detach().cpu().numpy()
            gnn_probs.extend(probs)
            gnn_preds.extend((probs > threshold).astype(int))
            all_targets.extend(data.y.detach().cpu().numpy())
    
    gnn_metrics = compute_metrics(all_targets, gnn_probs, gnn_preds)
    baseline_results['GNN'] = gnn_metrics
    
    print("  Computing heuristic baselines...")
    in_dim = dataset[0].x.shape[1] if dataset else 11
    if in_dim == 11:
        heuristics = [
            (0, 'in_degree'),
            (1, 'out_degree'),
            (3, 'is_loop_header'),
            (4, 'is_library_call'),
            (5, 'num_instructions'),
            (6, 'has_unsafe_call'),
            (7, 'has_memory_write'),
            (8, 'num_symbolic_variables'),
            (9, 'num_path_constraints'),
        ]
    else:
        heuristics = [
            (7, 'flow_centrality'),
            (25, 'has_memory_write'),
            (3, 'is_loop_header'),
            (14, 'is_library_call'),
            (17, 'has_unsafe_string'),
            (18, 'has_format_string'),
            (26, 'num_symbolic_variables'),
        ]
    
    for feat_idx, feat_name in heuristics:
        if feat_idx < in_dim:
            probs = []
            targets = []
            for data in dataset:
                targets.extend(data.y.cpu().numpy())
                probs.extend(data.x[:, feat_idx].cpu().numpy())
            
            if len(set(targets)) > 1:
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
    
    all_data = []
    with torch.no_grad():
        for data in dataset:
            data = data.to(device)
            out = model(data.x, data.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)[:, 1].detach().cpu().numpy()
            targets = data.y.detach().cpu().numpy()
            preds = (probs > threshold).astype(int)
            all_data.append((targets, probs, preds))
    
    f1_scores = []
    roc_aucs = []
    precisions = []
    recalls = []
    
    for _ in range(n_bootstrap):
        # Sample with replacement at the graph level
        indices = np.random.choice(len(all_data), size=len(all_data), replace=True)
        boot_data = [all_data[idx] for idx in indices]
        
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
        return (float(np.percentile(values, 2.5)), float(np.percentile(values, 97.5)))
    
    ci_results = {
        'f1': {'mean': float(np.mean(f1_scores)), 'ci95': ci(f1_scores)},
        'roc_auc': {'mean': float(np.mean(roc_aucs)), 'ci95': ci(roc_aucs)},
        'precision': {'mean': float(np.mean(precisions)), 'ci95': ci(precisions)},
        'recall': {'mean': float(np.mean(recalls)), 'ci95': ci(recalls)}
    }

    print(f"\nBootstrap 95% Confidence Intervals:")
    print(f"  F1:          {ci_results['f1']['mean']:.4f} [{ci_results['f1']['ci95'][0]:.4f}, {ci_results['f1']['ci95'][1]:.4f}]")
    print(f"  ROC-AUC:     {ci_results['roc_auc']['mean']:.4f} [{ci_results['roc_auc']['ci95'][0]:.4f}, {ci_results['roc_auc']['ci95'][1]:.4f}]")
    print(f"  Precision:   {ci_results['precision']['mean']:.4f} [{ci_results['precision']['ci95'][0]:.4f}, {ci_results['precision']['ci95'][1]:.4f}]")
    print(f"  Recall:      {ci_results['recall']['mean']:.4f} [{ci_results['recall']['ci95'][0]:.4f}, {ci_results['recall']['ci95'][1]:.4f}]")
    return ci_results


def ablation_study(model, dataset, device, temperature, threshold):
    """Ablation: evaluate impact of each feature group."""
    print("\n[+] Running ablation study...")
    
    in_dim = dataset[0].x.shape[1] if dataset else 11
    if in_dim == 11:
        feature_groups = {
            'structural': [0, 1, 2, 3],
            'api_calls': [4, 6],
            'instructions': [5, 7],
            'symbolic_state': [8, 9, 10],
        }
    else:
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
    with torch.no_grad():
        for data in dataset:
            data = data.to(device)
            out = model(data.x, data.edge_index)
            out = out / temperature
            probs = torch.softmax(out, dim=1)[:, 1].detach().cpu().numpy()
            all_probs.extend(probs)
            all_targets.extend(data.y.detach().cpu().numpy())
        
        full_preds = (np.array(all_probs) > threshold).astype(int)
        full_metrics = compute_metrics(all_targets, all_probs, full_preds)
        print(f"  Full model ({in_dim} features): F1={full_metrics['f1']:.4f}, AUC={full_metrics['roc_auc']:.4f}")
        
        ablation_results = {'full': full_metrics, 'groups': {}}
        
        for group_name, indices in feature_groups.items():
            probs_list = []
            targets_list = []
            for data in dataset:
                x = data.x.clone()
                x[:, indices] = 0.0
                data_mod = data.clone()
                data_mod.x = x
                data_mod = data_mod.to(device)
                
                out = model(data_mod.x, data_mod.edge_index)
                out = out / temperature
                probs = torch.softmax(out, dim=1)[:, 1].detach().cpu().numpy()
                probs_list.extend(probs)
                targets_list.extend(data.y.detach().cpu().numpy())
            
            preds = (np.array(probs_list) > threshold).astype(int)
            metrics = compute_metrics(targets_list, probs_list, preds)
            drop_f1 = full_metrics['f1'] - metrics['f1']
            drop_auc = full_metrics['roc_auc'] - metrics['roc_auc']
            ablation_results['groups'][group_name] = {
                'metrics': metrics,
                'drop_f1': float(drop_f1),
                'drop_auc': float(drop_auc)
            }
            print(f"  Without {group_name:14s}: F1={metrics['f1']:.4f} (Δ={drop_f1:+.4f}), "
                  f"AUC={metrics['roc_auc']:.4f} (Δ={drop_auc:+.4f})")
    
    return ablation_results


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
    
    # Evaluate per CWE and per binary
    cwe_results, binary_results, all_targets, all_probs, all_preds = evaluate_per_cwe(
        model, dataset, device, temperature, threshold
    )
    
    if args.per_cwe:
        print_cwe_table(cwe_results)
    
    # Overall metrics
    overall = compute_metrics(all_targets, all_probs, all_preds)
    top1_count = sum(1 for b in binary_results.values() if b.get('top1_hit'))
    top5_count = sum(1 for b in binary_results.values() if b.get('top5_hit'))
    top10_count = sum(1 for b in binary_results.values() if b.get('top10_hit'))
    total_bins = len(binary_results)
    
    overall['top1_hit_rate'] = float(top1_count / total_bins) if total_bins > 0 else 0.0
    overall['top5_hit_rate'] = float(top5_count / total_bins) if total_bins > 0 else 0.0
    overall['top10_hit_rate'] = float(top10_count / total_bins) if total_bins > 0 else 0.0
    overall['top1_count'] = top1_count
    overall['top5_count'] = top5_count
    overall['total_graphs'] = total_bins

    print("\n[+] Overall Metrics:")
    for k, v in overall.items():
        if isinstance(v, float):
            print(f"  {k}: {v:.4f}")
        elif isinstance(v, int):
            print(f"  {k}: {v}")
        else:
            print(f"  {k}: {v}")
    
    print(f"\n[+] Path Prioritization Ranking Performance:")
    print(f"  Top-1 Hit Rate:  {overall['top1_hit_rate']*100:.2f}% ({top1_count}/{total_bins})")
    print(f"  Top-5 Hit Rate:  {overall['top5_hit_rate']*100:.2f}% ({top5_count}/{total_bins})")
    print(f"  Top-10 Hit Rate: {overall['top10_hit_rate']*100:.2f}% ({top10_count}/{total_bins})")

    baseline_results = None
    if args.compare_baseline:
        baseline_results = compare_with_baseline(model, dataset, device, temperature, threshold)
    
    ci_results = None
    if args.bootstrap:
        ci_results = statistical_significance(model, dataset, device, temperature, threshold)
    
    ablation_results = None
    if args.ablation:
        ablation_results = ablation_study(model, dataset, device, temperature, threshold)
    
    # Save results
    if args.output:
        results = {
            'overall': overall,
            'per_cwe': {},
            'per_binary': binary_results,
            'config': {
                'model_path': args.model_path,
                'dataset_dir': args.dataset_dir,
                'temperature': temperature,
                'threshold': threshold,
                'num_graphs': len(dataset),
                'feature_dim': dataset[0].x.shape[1] if dataset else 11
            }
        }
        
        for cwe, r in cwe_results.items():
            if r['targets']:
                results['per_cwe'][cwe] = compute_metrics(r['targets'], r['probs'], r['preds'])
                results['per_cwe'][cwe]['num_binaries'] = len(r['binaries'])
        
        if baseline_results:
            results['baselines'] = baseline_results
        if ci_results:
            results['bootstrap_ci'] = ci_results
        if ablation_results:
            results['ablation'] = ablation_results

        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {args.output}")
    
    print("\n[+] Evaluation complete!")


if __name__ == "__main__":
    main()