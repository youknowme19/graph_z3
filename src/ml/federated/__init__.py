"""
Federated Learning module for GRAPH_Z3 using the Flower (flwr) framework.
Enables distributed, privacy-preserving training of VulnGNN across independent
organizations without sharing proprietary binary Control Flow Graphs.
"""

from .client import FlowerVulnClient, create_client
from .server import create_federated_strategy, aggregate_eval_metrics

__all__ = [
    "FlowerVulnClient",
    "create_client",
    "create_federated_strategy",
    "aggregate_eval_metrics",
]
