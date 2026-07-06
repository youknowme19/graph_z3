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
            if hasattr(data, 'y') and data.y is not None:
                dataset.append(data)
            else:
                print(f"[!] Skipping {file_path.name}: no labels")
        except Exception as e:
            print(f"[-] Error loading {file_path.name}: {e}")
    
    if not dataset:
        print("[-] No valid graphs found in dataset directory. Cannot train.")
        return
    
    print(f"[+] Loaded {len(dataset)} graphs from {len(set(_get_binary_name_from_graph(d) for d in dataset))} binaries")
    
    # Print feature dimension
    sample = dataset[0]
    print(f"[+] Feature dimension: {sample.x.shape[1]} (expected: {len(FEATURE_NAMES)})")
    assert sample.x.shape[1] == len(FEATURE_NAMES), \
        f"Feature dim mismatch: {sample.x.shape[1]} vs {len(FEATURE_NAMES)}"
    
    # 2. Split by binary (no data leakage!)
    train_data, val_data, test_data = _split_by_binary(dataset, seed=seed)
    print(f"[+] Split: Train={len(train_data)}, Val={len(val_data)}, Test={len(test_data)}")
    
    # DataLoaders
    train_loader = DataLoader(train_data, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=batch_size, shuffle=False)
    test_loader = DataLoader(test_data, batch_size=batch_size, shuffle=False)
    
    # 3. Initialize Model, Loss, Optimizer
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[+] Training on device: {device}")
    
    model = create_model(
        input_dim=len(FEATURE_NAMES),
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        encoder=encoder,
        dropout=dropout
    ).to(device)
    
    # Class weights
    weight = _compute_class_weights(train_data, device)
    criterion = nn.CrossEntropyLoss(weight=weight)
    
    optimizer = optim.AdamW(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode='min', factor=0.5, patience=5, verbose=True
    )
    
    # Training state
    best_val_loss = float('inf')
    best_epoch = 0
    epochs_no_improve = 0
    history = {
        'train_loss': [], 'val_loss': [],
        'train_f1': [], 'val_f1': [],
        'val_roc_auc': [], 'val_avg_prec': [],
        'lr': []
    }
    
    print(f"[+] Starting training for {epochs} epochs...")
    print(f"[+] Early stopping patience: {patience}")
    print(f"[+] Model config: hidden_dim={hidden_dim}, layers={num_layers}, encoder={encoder}, dropout={dropout}")
    
    # 4. Training Loop
    for epoch in range(1, epochs + 1):
        model.train()
        total_loss = 0
        all_preds = []
        all_targets = []
        
        for batch in train_loader:
            batch = batch.to(device)
            optimizer.zero_grad()
            
            out = model(batch.x, batch.edge_index)
            loss = criterion(out, batch.y)
            
            loss.backward()
            # Gradient clipping for stability
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            optimizer.step()
            
            total_loss += loss.item() * batch.num_graphs
            preds = out.argmax(dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_targets.extend(batch.y.cpu().numpy())
        
        avg_train_loss = total_loss / len(train_data)
        
        train_precision, train_recall, train_f1, _ = precision_recall_fscore_support(
            all_targets, all_preds, average='binary', zero_division=0
        )
        
        # Validation
        val_metrics = _evaluate_model(model, val_loader, criterion, device)
        avg_val_loss = val_metrics['loss']
        val_f1 = val_metrics['f1']
        val_roc_auc = val_metrics['roc_auc']
        val_avg_prec = val_metrics['avg_precision']
        
        # Learning rate scheduling
        scheduler.step(avg_val_loss)
        current_lr = optimizer.param_groups[0]['lr']
        
        # Record history
        history['train_loss'].append(avg_train_loss)
        history['val_loss'].append(avg_val_loss)
        history['train_f1'].append(train_f1)
        history['val_f1'].append(val_f1)
        history['val_roc_auc'].append(val_roc_auc)
        history['val_avg_prec'].append(val_avg_prec)
        history['lr'].append(current_lr)
        
        # Logging
        if epoch % 5 == 0 or epoch == 1 or epoch == epochs:
            print(f"Epoch {epoch:03d}/{epochs:03d} | "
                  f"Train Loss: {avg_train_loss:.4f} | Train F1: {train_f1:.4f} | "
                  f"Val Loss: {avg_val_loss:.4f} | Val F1: {val_f1:.4f} | "
                  f"Val ROC-AUC: {val_roc_auc:.4f} | Val AP: {val_avg_prec:.4f} | "
                  f"LR: {current_lr:.2e}")
        
        # Checkpoint best model
        if avg_val_loss < best_val_loss:
            best_val_loss = avg_val_loss
            best_epoch = epoch
            epochs_no_improve = 0
            
            torch.save({
                'epoch': epoch,
                'model_state_dict': model.state_dict(),
                'optimizer_state_dict': optimizer.state_dict(),
                'scheduler_state_dict': scheduler.state_dict(),
                'best_val_loss': best_val_loss,
                'config': {
                    'input_dim': len(FEATURE_NAMES),
                    'hidden_dim': hidden_dim,
                    'num_layers': num_layers,
                    'encoder': encoder,
                    'dropout': dropout,
                },
                'history': history,
                'feature_names': FEATURE_NAMES,
            }, model_path)
        else:
            epochs_no_improve += 1
        
        # Early stopping
        if epochs_no_improve >= patience:
            print(f"[+] Early stopping at epoch {epoch} (best epoch: {best_epoch})")
            break
    
    print(f"\n[+] Training completed. Best epoch: {best_epoch}, Best val loss: {best_val_loss:.4f}")
    print(f"[+] Best model checkpoint saved to {model_path}")
    
    # 5. Temperature Scaling on validation set
    print("[+] Finding optimal temperature for calibration...")
    checkpoint = torch.load(model_path, map_location=device)
    model.load_state_dict(checkpoint['model_state_dict'])
    optimal_temp = _find_optimal_temperature(model, val_loader, device)
    model.set_temperature(optimal_temp)
    
    # Save temperature
    temp_path = model_path.replace('.pt', '_temperature.json')
    with open(temp_path, 'w') as f:
        json.dump({'temperature': optimal_temp}, f)
    print(f"[+] Temperature saved to {temp_path}")
    
    # 6. Final evaluation on test set
    print("\n[+] Final evaluation on TEST set...")
    test_metrics = _evaluate_model(model, test_loader, criterion, device, temperature=optimal_temp)
    
    print(f"Test Loss: {test_metrics['loss']:.4f}")
    print(f"Test Precision: {test_metrics['precision']:.4f}")
    print(f"Test Recall: {test_metrics['recall']:.4f}")
    print(f"Test F1: {test_metrics['f1']:.4f}")
    print(f"Test ROC-AUC: {test_metrics['roc_auc']:.4f}")
    print(f"Test Avg Precision: {test_metrics['avg_precision']:.4f}")
    print(f"Confusion Matrix:\n{np.array(test_metrics['confusion_matrix'])}")
    
    # Per-graph statistics
    pg = test_metrics['per_graph']
    if pg:
        print(f"\nPer-graph stats (n={len(pg)}):")
        print(f"  Avg nodes per graph: {np.mean([g['num_nodes'] for g in pg]):.1f}")
        print(f"  Avg vuln nodes per graph: {np.mean([g['num_vuln'] for g in pg]):.2f}")
        print(f"  Avg graph accuracy: {np.mean([g['accuracy'] for g in pg]):.4f}")
        print(f"  Avg graph AUC: {np.mean([g['auc'] for g in pg]):.4f}")
        print(f"  Avg graph AP: {np.mean([g['ap'] for g in pg]):.4f}")
    
    # Save detailed results
    results_path = model_path.replace('.pt', '_results.json')
    with open(results_path, 'w') as f:
        json.dump({
            'best_epoch': best_epoch,
            'best_val_loss': best_val_loss,
            'temperature': optimal_temp,
            'test_metrics': test_metrics,
            'history': history,
            'config': checkpoint['config']
        }, f, indent=2)
    print(f"[+] Detailed results saved to {results_path}")
    
    # 7. Find optimal classification threshold on validation set
    print("[+] Finding optimal classification threshold...")
    optimal_threshold = _find_optimal_threshold(model, val_loader, device, optimal_temp)
    thresh_path = model_path.replace('.pt', '_threshold.json')
    with open(thresh_path, 'w') as f:
        json.dump({'threshold': optimal_threshold}, f)
    print(f"[+] Optimal threshold: {optimal_threshold:.3f} (saved to {thresh_path})")
    
    # Print classification report
    if test_metrics['targets']:
        print("\n[+] Test Set Classification Report:")
        print(classification_report(
            test_metrics['targets'], 
            test_metrics['predictions'], 
            target_names=["Safe", "Vulnerable"], 
            zero_division=0
        ))
    
    return model, test_metrics


def evaluate_model(model_path, dataset_dir, temperature_path=None):
    """Evaluate a trained model on a dataset."""
    if torch is None:
        raise ImportError("PyTorch required.")
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    
    # Load model
    checkpoint = torch.load(model_path, map_location=device)
    config = checkpoint['config']
    
    model = create_model(**config).to(device)
    model.load_state_dict(checkpoint['model_state_dict'])
    
    # Load temperature if available
    if temperature_path and os.path.exists(temperature_path):
        with open(temperature_path) as f:
            temp_data = json.load(f)
        model.set_temperature(temp_data['temperature'])
        print(f"[+] Loaded temperature: {temp_data['temperature']:.3f}")
    
    # Load dataset
    dataset = []
    for file_path in Path(dataset_dir).glob("*.pt"):
        try:
            data = torch.load(file_path, weights_only=False)
            data.binary_name = file_path.stem
            if hasattr(data, 'y') and data.y is not None:
                dataset.append(data)
        except Exception as e:
            print(f"[-] Error loading {file_path.name}: {e}")
    
    if not dataset:
        print("[-] No valid graphs found.")
        return
    
    # Evaluate
    loader = DataLoader(dataset, batch_size=8, shuffle=False)
    criterion = nn.CrossEntropyLoss()
    
    metrics = _evaluate_model(model, loader, criterion, device, temperature=model.get_temperature())
    
    print(f"Loss: {metrics['loss']:.4f}")
    print(f"Precision: {metrics['precision']:.4f}")
    print(f"Recall: {metrics['recall']:.4f}")
    print(f"F1: {metrics['f1']:.4f}")
    print(f"ROC-AUC: {metrics['roc_auc']:.4f}")
    print(f"Avg Precision: {metrics['avg_precision']:.4f}")
    print(f"Confusion Matrix:\n{np.array(metrics['confusion_matrix'])}")
    
    return metrics


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the GNN vulnerability detector model.")
    parser.add_argument("--dataset-dir", type=str, required=True, help="Directory containing .pt graphs")
    parser.add_argument("--epochs", type=int, default=100, help="Number of training epochs")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--model-path", type=str, default="model.pt", help="Path to save the trained model (.pt)")
    parser.add_argument("--hidden-dim", type=int, default=128, help="Hidden dimension")
    parser.add_argument("--num-layers", type=int, default=3, help="Number of GNN layers")
    parser.add_argument("--encoder", type=str, default='sage', choices=['sage', 'gat'], help="Encoder type")
    parser.add_argument("--dropout", type=float, default=0.3, help="Dropout rate")
    parser.add_argument("--batch-size", type=int, default=8, help="Batch size")
    parser.add_argument("--patience", type=int, default=15, help="Early stopping patience")
    parser.add_argument("--weight-decay", type=float, default=1e-4, help="Weight decay")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--eval-only", action="store_true", help="Only evaluate existing model")
    parser.add_argument("--temperature-path", type=str, help="Path to temperature file for eval")
    
    args = parser.parse_args()
    
    if args.eval_only:
        if not os.path.exists(args.model_path):
            print(f"[-] Model not found at {args.model_path}")
            sys.exit(1)
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
            seed=args.seed
        )