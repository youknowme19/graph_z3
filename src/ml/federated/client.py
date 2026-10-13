"""
Flower Client Implementation for GRAPH_Z3.

Wraps VulnGNN inside a flwr.client.NumPyClient to perform privacy-preserving
local graph neural network training on private binary CFG datasets.
"""

from typing import Dict, List, Tuple, Optional, Any
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
except ImportError:
    torch = None

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


class FlowerVulnClient(NumPyClient if FLWR_AVAILABLE else object):
    """
    Flower NumPyClient for VulnGNN.
    
    Each client represents an enterprise, defense contractor, or security lab
    possessing private binary samples and their extracted Control Flow Graphs.
    """

    def __init__(
        self,
        client_id: str,
        model: Any,
        train_loader: Any,
        val_loader: Any,
        device: Optional[str] = None,
        learning_rate: float = 0.001,
        local_epochs: int = 3,
        class_weights: Optional[Any] = None,
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

        # Setup loss criterion
        if class_weights is not None:
            weight_tensor = torch.tensor(class_weights, dtype=torch.float, device=self.device)
            self.criterion = nn.CrossEntropyLoss(weight=weight_tensor)
        else:
            self.criterion = nn.CrossEntropyLoss()

    def get_parameters(self, config: Dict[str, Any]) -> List[np.ndarray]:
        """Extract model parameters as a list of NumPy arrays."""
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]

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
        Train the model locally on private CFG graphs.
        
        Args:
            parameters: Global model parameters from server.
            config: Server training configuration (e.g., local epochs, learning rate).
            
        Returns:
            Tuple of (updated parameters, dataset size, training metrics dictionary).
        """
        self.set_parameters(parameters)
        
        epochs = config.get("local_epochs", self.local_epochs)
        lr = config.get("lr", self.learning_rate)

        optimizer = optim.AdamW(
            self.model.parameters(), lr=lr, weight_decay=1e-4
        )

        self.model.train()
        total_loss = 0.0
        num_batches = 0

        for epoch in range(epochs):
            epoch_loss = 0.0
            for batch in self.train_loader:
                batch = batch.to(self.device)
                optimizer.zero_grad()

                out = self.model(batch.x, batch.edge_index)
                loss = self.criterion(out, batch.y)
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=1.0)
                optimizer.step()

                epoch_loss += loss.item()
                num_batches += 1

            total_loss += epoch_loss

        avg_loss = total_loss / max(1, num_batches)
        num_examples = len(self.train_loader.dataset) if hasattr(self.train_loader, "dataset") else len(self.train_loader)

        metrics = {
            "client_id": self.client_id,
            "train_loss": float(avg_loss),
            "epochs": epochs,
        }

        return self.get_parameters(config={}), num_examples, metrics

    def evaluate(
        self, parameters: List[np.ndarray], config: Dict[str, Any]
    ) -> Tuple[float, int, Dict[str, Any]]:
        """
        Evaluate global model on client's local validation dataset.
        
        Returns:
            Tuple of (loss, dataset size, metrics dictionary).
        """
        self.set_parameters(parameters)
        self.model.eval()

        total_loss = 0.0
        all_preds = []
        all_targets = []
        all_probs = []

        with torch.no_grad():
            for batch in self.val_loader:
                batch = batch.to(self.device)
                out = self.model(batch.x, batch.edge_index)
                loss = self.criterion(out, batch.y)
                total_loss += loss.item()

                probs = torch.softmax(out, dim=1)
                preds = probs.argmax(dim=1)

                all_preds.extend(preds.cpu().numpy())
                all_targets.extend(batch.y.cpu().numpy())
                all_probs.extend(probs[:, 1].cpu().numpy())

        num_examples = len(self.val_loader.dataset) if hasattr(self.val_loader, "dataset") else len(self.val_loader)
        avg_loss = total_loss / max(1, len(self.val_loader))

        y_true = np.array(all_targets)
        y_pred = np.array(all_preds)

        # Compute classification metrics
        accuracy = float((y_true == y_pred).mean()) if len(y_true) > 0 else 0.0
        
        # Calculate precision, recall, f1
        tp = np.sum((y_true == 1) & (y_pred == 1))
        fp = np.sum((y_true == 0) & (y_pred == 1))
        fn = np.sum((y_true == 1) & (y_pred == 0))

        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        metrics = {
            "client_id": self.client_id,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

        return float(avg_loss), num_examples, metrics


def create_client(
    client_id: str,
    train_loader: Any,
    val_loader: Any,
    input_dim: int = 11,
    hidden_dim: int = 128,
    num_layers: int = 3,
    encoder: str = "sage",
    device: Optional[str] = None,
    learning_rate: float = 0.001,
    local_epochs: int = 3,
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
    )
