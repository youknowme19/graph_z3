"""
Unit tests for Federated Learning with Flower in GRAPH_Z3.
"""

import unittest
import numpy as np
import sys
import os

# Add root directory to sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from src.ml.federated.server import aggregate_eval_metrics, create_federated_strategy, FLWR_AVAILABLE
from src.ml.federated.simulation import partition_dataset_non_iid, generate_synthetic_cfgs


class TestFederatedLearning(unittest.TestCase):
    def test_aggregate_eval_metrics_weighted(self):
        """Verify sample-count weighted averaging for client evaluation metrics."""
        client_metrics = [
            (100, {"accuracy": 0.80, "precision": 0.85, "recall": 0.75, "f1": 0.796}),
            (200, {"accuracy": 0.90, "precision": 0.95, "recall": 0.85, "f1": 0.897}),
        ]
        agg = aggregate_eval_metrics(client_metrics)
        # Expected accuracy = (100*0.80 + 200*0.90) / 300 = (80 + 180)/300 = 260/300 = 0.8666...
        self.assertAlmostEqual(agg["accuracy"], 260.0 / 300.0, places=4)
        # Expected precision = (100*0.85 + 200*0.95) / 300 = (85 + 190)/300 = 275/300 = 0.9166...
        self.assertAlmostEqual(agg["precision"], 275.0 / 300.0, places=4)

    def test_empty_metrics(self):
        """Verify graceful return on empty client metrics."""
        agg = aggregate_eval_metrics([])
        self.assertEqual(agg, {})

    def test_partition_dataset_non_iid(self):
        """Test dataset partitioning across simulated clients."""
        dataset = list(range(30))
        partitions = partition_dataset_non_iid(dataset, num_clients=3)
        self.assertEqual(len(partitions), 3)
        self.assertEqual(len(partitions[0]), 10)
        self.assertEqual(len(partitions[1]), 10)
        self.assertEqual(len(partitions[2]), 10)

    def test_synthetic_cfg_generator(self):
        """Test CFG synthetic graph generation."""
        try:
            import torch
            graphs = generate_synthetic_cfgs(num_graphs=5, num_nodes=15, feat_dim=11)
            self.assertEqual(len(graphs), 5)
            self.assertEqual(graphs[0].x.shape, (15, 11))
            self.assertEqual(len(graphs[0].y), 15)
        except ImportError:
            self.skipTest("PyTorch is not available for synthetic CFG test.")

    def test_strategy_creation(self):
        """Test Flower strategy factory creation if Flower is installed."""
        if not FLWR_AVAILABLE:
            self.skipTest("Flower (flwr) not installed in current environment.")
        strategy_fedprox = create_federated_strategy("fedprox", min_fit_clients=2)
        strategy_fedavg = create_federated_strategy("fedavg", min_fit_clients=2)
        self.assertIsNotNone(strategy_fedprox)
        self.assertIsNotNone(strategy_fedavg)


if __name__ == "__main__":
    unittest.main()
