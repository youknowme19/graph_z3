"""
Flower Server Strategies and Metric Aggregation for GRAPH_Z3.

Supports:
- FedAvg (Federated Averaging)
- FedProx (Federated Proximal for handling Non-IID client heterogeneity)
- Weighted metric aggregation (Precision, Recall, F1, Accuracy)
"""

from typing import Dict, List, Tuple, Optional, Any
import numpy as np

try:
    import flwr as fl
    from flwr.server.strategy import FedAvg, FedProx
    FLWR_AVAILABLE = True
except ImportError:
    FLWR_AVAILABLE = False
    FedAvg = object
    FedProx = object

from src.ml.gnn_model import create_model


def aggregate_eval_metrics(metrics: List[Tuple[int, Dict[str, Any]]]) -> Dict[str, float]:
    """
    Weighted average of client validation metrics based on sample counts.
    
    Args:
        metrics: List of tuples (num_examples, client_metrics_dict)
        
    Returns:
        Aggregated metrics dictionary.
    """
    total_examples = sum(num_examples for num_examples, _ in metrics)
    if total_examples == 0:
        return {}

    agg: Dict[str, float] = {
        "accuracy": 0.0,
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
    }

    for num_examples, m in metrics:
        weight = num_examples / total_examples
        for key in agg.keys():
            if key in m:
                agg[key] += float(m[key]) * weight

    return agg


def create_federated_strategy(
    strategy_name: str = "fedprox",
    fraction_fit: float = 1.0,
    fraction_evaluate: float = 1.0,
    min_fit_clients: int = 2,
    min_evaluate_clients: int = 2,
    min_available_clients: int = 2,
    proximal_mu: float = 0.1,
    initial_parameters: Optional[Any] = None,
) -> Any:
    """
    Constructs a Flower federated learning strategy.
    
    Args:
        strategy_name: 'fedavg' or 'fedprox' (recommended for non-IID CFGs).
        fraction_fit: Fraction of clients selected for training each round.
        fraction_evaluate: Fraction of clients selected for evaluation.
        min_fit_clients: Minimum clients required for training.
        min_evaluate_clients: Minimum clients required for evaluation.
        min_available_clients: Minimum available clients before round starts.
        proximal_mu: Proximal regularization weight for FedProx.
        initial_parameters: Starting model weights (flwr.common.ndarrays_to_parameters).
        
    Returns:
        Flower Strategy instance.
    """
    if not FLWR_AVAILABLE:
        raise ImportError(
            "Flower framework is not installed. Install via: pip install 'flwr>=1.7.0'"
        )

    strategy_kwargs = {
        "fraction_fit": fraction_fit,
        "fraction_evaluate": fraction_evaluate,
        "min_fit_clients": min_fit_clients,
        "min_evaluate_clients": min_evaluate_clients,
        "min_available_clients": min_available_clients,
        "evaluate_metrics_aggregation_fn": aggregate_eval_metrics,
        "initial_parameters": initial_parameters,
    }

    if strategy_name.lower() == "fedprox":
        return FedProx(
            proximal_mu=proximal_mu,
            **strategy_kwargs,
        )
    elif strategy_name.lower() == "fedavg":
        return FedAvg(**strategy_kwargs)
    else:
        raise ValueError(f"Unsupported strategy '{strategy_name}'. Choose 'fedavg' or 'fedprox'.")


def get_initial_parameters(
    input_dim: int = 11,
    hidden_dim: int = 128,
    num_layers: int = 3,
    encoder: str = "sage",
) -> Any:
    """Returns initial model parameters serialized for Flower."""
    if not FLWR_AVAILABLE:
        raise ImportError("Flower is required.")
    import flwr.common as fl_common
    
    model = create_model(
        input_dim=input_dim,
        hidden_dim=hidden_dim,
        num_layers=num_layers,
        encoder=encoder,
    )
    ndarrays = [val.cpu().numpy() for _, val in model.state_dict().items()]
    return fl_common.ndarrays_to_parameters(ndarrays)
