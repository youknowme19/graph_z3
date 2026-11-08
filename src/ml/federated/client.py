"""
Flower Client Implementation for NeuroZ3 (GRAPH_Z3).

Wraps 40-dimensional Bidirectional VulnGNN inside a flwr.client.NumPyClient to perform
privacy-preserving local graph neural network training on real stripped binary CFG datasets
with Focal Cross-Entropy Loss and FedProx proximal regularization.
"""

from typing import Dict, List, Tuple, Optional, Any
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import torch.optim as optim
except ImportError:
    torch = None
    nn = None
    F = None
    optim = None

try:
    from torch_geometric.loader import DataLoader
except ImportError:
    DataLoader = None

try:
    import flwr as fl
    from flwr.client import NumPyClient
    FLWR_AVAILABLE = True
except ImportError:
    FLWR_AVAILABLE = False
    NumPyClient = object

from src.ml.gnn_model import VulnGNN, create_model
from src.ml.trainer import FocalCrossEntropyLoss, _compute_class_weights


class FlowerVulnClient(NumPyClient if FLWR_AVAILABLE else object):
    """
    Flower NumPyClient for VulnGNN.

    Each client represents an enterprise, kernel team, defense contractor, or security lab
    training locally on private stripped binary Control Flow Graphs.
    """

    def __init__(
        self,
        client_id: str,
        model: Any,
        train_loader: Any,
        val_loader: Any,
        device: Optional[str] = None,
        learning_rate: float = 0.0012,
        local_epochs: int = 6,
        class_weights: Optional[Any] = None,
        proximal_mu: float = 0.002,
    ):
        if not FLWR_AVAILABLE:
            raise ImportError(
                "Flower framework is not installed. Install via: pip install 'flwr>=1.7.0'"
            )
        if torch is None:
            raise ImportError("PyTorch must be installed for FlowerVulnClient.")

        self.client_id = client_id
        self.model = model
        self.train_loader = train_loader
        self.val_loader = val_loader
        self.device = (
            torch.device(device)
            if device
            else torch.device("cuda" if torch.cuda.is_available() else "cpu")
        )
        self.model.to(self.device)
        self.learning_rate = learning_rate
        self.local_epochs = local_epochs
        self.default_proximal_mu = proximal_mu

        # Setup Focal Cross-Entropy Loss with inverse-sqrt class weights for extreme node imbalance
        if class_weights is not None:
            weight_tensor = (
                class_weights.to(self.device)
                if isinstance(class_weights, torch.Tensor)
                else torch.tensor(class_weights, dtype=torch.float, device=self.device)
            )
        elif hasattr(train_loader, "dataset") and len(train_loader.dataset) > 0:
            weight_tensor = _compute_class_weights(list(train_loader.dataset), self.device)
        else:
            weight_tensor = torch.tensor([1.0, 15.0], dtype=torch.float, device=self.device)

        self.criterion = FocalCrossEntropyLoss(weight=weight_tensor, gamma=2.0)

    def get_parameters(self, config: Dict[str, Any]) -> List[np.ndarray]:
        """Extract model parameters as a list of NumPy arrays."""
        return [val.detach().cpu().numpy() for _, val in self.model.state_dict().items()]

    def set_parameters(self, parameters: List[np.ndarray]) -> None:
        """Update model parameters from aggregated global weights."""
        state_dict = self.model.state_dict()
        for k, v in zip(state_dict.keys(), parameters):
            state_dict[k] = torch.tensor(v, dtype=state_dict[k].dtype, device=self.device)
        self.model.load_state_dict(state_dict, strict=True)

    def fit(
        self, parameters: List[np.ndarray], config: Dict[str, Any]
    ) -> Tuple[List[np.ndarray], int, Dict[str, Any]]:
        """
        Train the model locally on private stripped binary CFG graphs using Focal Loss
        and FedProx proximal regularization:
            min_w F_k(w) + (mu / 2) * ||w - w^t||_2^2
        """
        self.set_parameters(parameters)
        global_params = [p.detach().clone() for p in self.model.parameters()]

        epochs = int(config.get("local_epochs", self.local_epochs))
        lr = float(config.get("lr", self.learning_rate))
        proximal_mu = float(config.get("proximal_mu", self.default_proximal_mu))

        optimizer = optim.AdamW(
            self.model.parameters(), lr=lr, weight_decay=1e-4
        )

        self.model.train()
        total_loss = 0.0
        num_batches = 0

        for _ in range(epochs):
            for batch in self.train_loader:
                batch = batch.to(self.device)
                optimizer.zero_grad()

                out = self.model(batch.x, batch.edge_index, getattr(batch, "batch", None))
                loss = self.criterion(out, batch.y)
                if proximal_mu > 0.0:
                    prox_term = sum(
                        ((lp - gp) ** 2).sum()
                        for lp, gp in zip(self.model.parameters(), global_params)
                    )
                    loss = loss + 0.5 * proximal_mu * prox_term

                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()

                total_loss += float(loss.item())
                num_batches += 1

        avg_loss = total_loss / max(1, num_batches)
        num_examples = (
            len(self.train_loader.dataset)
            if hasattr(self.train_loader, "dataset")
            else len(self.train_loader)
        )

        metrics = {
            "client_id": self.client_id,
            "train_loss": float(avg_loss),
            "epochs": epochs,
            "proximal_mu": proximal_mu,
        }

        return self.get_parameters(config={}), num_examples, metrics

    def evaluate(
        self, parameters: List[np.ndarray], config: Dict[str, Any]
    ) -> Tuple[float, int, Dict[str, Any]]:
        """
        Evaluate global model on client's local held-out validation dataset,
        computing node-level F1/ROC-AUC/PR-AUC and per-binary Top-1/Top-5 hit rates.
        """
        from sklearn.metrics import roc_auc_score, average_precision_score

        self.set_parameters(parameters)
        self.model.eval()

        total_loss = 0.0
        all_preds = []
        all_targets = []
        all_probs = []
        top1_hits = 0
        top5_hits = 0
        vuln_graphs = 0

        with torch.no_grad():
            for batch in self.val_loader:
                batch = batch.to(self.device)
                out = self.model(batch.x, batch.edge_index, getattr(batch, "batch", None))
                loss = self.criterion(out, batch.y)
                total_loss += float(loss.item())

                probs = torch.softmax(out, dim=1)[:, 1]
                preds = (probs >= 0.5).long()

                all_preds.extend(preds.cpu().numpy())
                all_targets.extend(batch.y.cpu().numpy())
                all_probs.extend(probs.cpu().numpy())

                # Per-graph Top-1 and Top-5 ranking accuracy
                if hasattr(batch, "ptr"):
                    ptr = batch.ptr.cpu().numpy()
                    y_np = batch.y.cpu().numpy()
                    p_np = probs.cpu().numpy()
                    for g_i in range(len(ptr) - 1):
                        s, e = int(ptr[g_i]), int(ptr[g_i + 1])
                        gy = y_np[s:e]
                        gp = p_np[s:e]
                        if gy.sum() > 0:
                            vuln_graphs += 1
                            ranked = np.argsort(gp)[::-1]
                            if gy[ranked[0]] == 1:
                                top1_hits += 1
                            if gy[ranked[: min(5, len(ranked))]].sum() > 0:
                                top5_hits += 1

        num_examples = (
            len(self.val_loader.dataset)
            if hasattr(self.val_loader, "dataset")
            else len(self.val_loader)
        )
        avg_loss = total_loss / max(1, len(self.val_loader))

        y_true = np.array(all_targets)
        y_pred = np.array(all_preds)
        y_prob = np.array(all_probs)

        accuracy = float((y_true == y_pred).mean()) if len(y_true) > 0 else 0.0
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))

        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        try:
            roc_auc = float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
            pr_auc = float(average_precision_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else 0.0
        except Exception:
            roc_auc, pr_auc = 0.0, 0.0

        metrics = {
            "client_id": self.client_id,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "top1_hit_rate": float(top1_hits / max(1, vuln_graphs)),
            "top5_hit_rate": float(top5_hits / max(1, vuln_graphs)),
        }

        return float(avg_loss), num_examples, metrics


def create_client(
    client_id: str,
    train_loader: Any,
    val_loader: Any,
    input_dim: int = 40,
    hidden_dim: int = 128,
    num_layers: int = 3,
    encoder: str = "sage",
    device: Optional[str] = None,
    learning_rate: float = 0.0012,
    local_epochs: int = 6,
    proximal_mu: float = 0.002,
) -> FlowerVulnClient:
    """Helper factory function to instantiate a FlowerVulnClient."""
    model = create_model(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        encoder=encoder,
    )
    return FlowerVulnClient(
        client_id=client_id,
        model=model,
        train_loader=train_loader,
        val_loader=val_loader,
        device=device,
        learning_rate=learning_rate,
        local_epochs=local_epochs,
        proximal_mu=proximal_mu,
    )
