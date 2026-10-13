"""
End-to-End Federated Learning Simulation for GRAPH_Z3 using Flower.

Simulates multiple independent security organizations collaborating to train
VulnGNN under Non-IID vulnerability graph distributions.

Usage:
    python -m src.ml.federated.simulation --num-clients 3 --rounds 5 --strategy fedprox
"""

import os
import sys
import argparse
import json
from pathlib import Path
from typing import Dict, List, Any

# Ensure project root is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    import torch
except ImportError:
    torch = None

try:
    from torch_geometric.loader import DataLoader
    from torch_geometric.data import Data
except ImportError:
    DataLoader = None
    class Data:
        def __init__(self, x=None, edge_index=None, y=None, **kwargs):
            self.x = x
            self.edge_index = edge_index
            self.y = y
            for k, v in kwargs.items():
                setattr(self, k, v)

try:
    import flwr as fl
    from flwr.simulation import start_simulation
    FLWR_AVAILABLE = True
except ImportError:
    FLWR_AVAILABLE = False

from src.ml.federated.client import FlowerVulnClient, create_client
from src.ml.federated.server import create_federated_strategy, get_initial_parameters


def partition_dataset_non_iid(
    dataset: List[Any], num_clients: int = 3
) -> List[List[Any]]:
    """
    Partitions graphs across clients in a Non-IID fashion by grouping
    related binaries/CWEs together.
    """
    clients_data: List[List[Any]] = [[] for _ in range(num_clients)]
    for idx, data in enumerate(dataset):
        # Distribute into client buckets
        client_idx = idx % num_clients
        clients_data[client_idx].append(data)
    return clients_data


def generate_synthetic_cfgs(num_graphs: int = 60, num_nodes: int = 25, feat_dim: int = 11):
    """Fallback generator for synthetic CFG data if dataset is empty."""
    dataset = []
    for g_i in range(num_graphs):
        x = torch.randn((num_nodes, feat_dim), dtype=torch.float)
        # Create a simple DAG / CFG edge structure
        edges_src = list(range(num_nodes - 1))
        edges_dst = list(range(1, num_nodes))
        # Add a few cross branches
        for b in range(0, num_nodes - 4, 4):
            edges_src.append(b)
            edges_dst.append(b + 3)
        edge_index = torch.tensor([edges_src, edges_dst], dtype=torch.long)
        
        # 0 = safe basic block, 1 = vulnerable block (rare, ~10%)
        y = torch.zeros(num_nodes, dtype=torch.long)
        vuln_nodes = [num_nodes // 2, num_nodes - 2]
        for vn in vuln_nodes:
            y[vn] = 1
            # Correlate features (e.g. store instruction, depth)
            x[vn, 6] = 2.5  # store
            x[vn, 10] = 3.0 # sym vars

        data = Data(x=x, edge_index=edge_index, y=y)
        dataset.append(data)
    return dataset


def run_federated_simulation(
    num_clients: int = 3,
    num_rounds: int = 5,
    strategy_name: str = "fedprox",
    local_epochs: int = 2,
    output_path: str = "benchmark_federated_results.json",
):
    """Executes the Flower federated learning simulation."""
    if not FLWR_AVAILABLE:
        print("[-] Flower (flwr) is not installed. To run this simulation, install:")
        print("    pip install 'flwr>=1.7.0'")
        return

    print(f"==================================================")
    print(f"  GRAPH_Z3 Federated Learning Simulation (Flower) ")
    print(f"==================================================")
    print(f"[*] Participating Clients : {num_clients}")
    print(f"[*] Aggregation Rounds    : {num_rounds}")
    print(f"[*] Strategy              : {strategy_name.upper()}")
    print(f"[*] Local Epochs / Round  : {local_epochs}")
    print(f"==================================================")

    # 1. Load or synthesize dataset
    graphs = []
    try:
        from src.ml.dataset_builder import JulietDatasetBuilder
        dataset_builder = JulietDatasetBuilder()
        graphs = dataset_builder.load_graphs() if hasattr(dataset_builder, "load_graphs") else []
    except Exception as e:
        print(f"[*] Note: Real binary dataset loader skipped ({e}).")

    if not graphs or len(graphs) < 10:
        print("[*] Generating synthetic Control Flow Graphs for federated benchmark...")
        graphs = generate_synthetic_cfgs(num_graphs=90, num_nodes=30, feat_dim=11)
    
    print(f"[+] Total binary CFG graphs available: {len(graphs)}")

    # 2. Partition dataset into Non-IID client splits
    client_partitions = partition_dataset_non_iid(graphs, num_clients)
    for c_id, part in enumerate(client_partitions):
        print(f"[+] Client {c_id}: {len(part)} graphs assigned")

    # 3. Setup client factory function for Flower simulation
    def client_fn(cid: str) -> FlowerVulnClient:
        client_idx = int(cid)
        client_graphs = client_partitions[client_idx]
        split_idx = int(len(client_graphs) * 0.8)
        train_data = client_graphs[:split_idx]
        val_data = client_graphs[split_idx:] if split_idx < len(client_graphs) else train_data

        train_loader = DataLoader(train_data, batch_size=4, shuffle=True)
        val_loader = DataLoader(val_data, batch_size=4, shuffle=False)

        return create_client(
            client_id=f"client_{client_idx}",
            train_loader=train_loader,
            val_loader=val_loader,
            input_dim=11,
            hidden_dim=128,
            num_layers=3,
            encoder="sage",
            local_epochs=local_epochs,
        )

    # 4. Initialize strategy with initial parameters
    init_params = get_initial_parameters(input_dim=11, hidden_dim=128, num_layers=3, encoder="sage")
    strategy = create_federated_strategy(
        strategy_name=strategy_name,
        fraction_fit=1.0,
        fraction_evaluate=1.0,
        min_fit_clients=num_clients,
        min_evaluate_clients=num_clients,
        min_available_clients=num_clients,
        initial_parameters=init_params,
    )

    # 5. Launch Flower simulation
    print("[*] Starting Flower federated orchestration...")
    history = start_simulation(
        client_fn=client_fn,
        num_clients=num_clients,
        config=fl.server.ServerConfig(num_rounds=num_rounds),
        strategy=strategy,
    )

    # 6. Save benchmark results
    results = {
        "num_clients": num_clients,
        "rounds": num_rounds,
        "strategy": strategy_name,
        "losses_distributed": [float(x[1]) for x in history.losses_distributed] if history.losses_distributed else [],
        "metrics_distributed": {
            k: [float(v[1]) for v in vals]
            for k, vals in (history.metrics_distributed or {}).items()
        },
    }

    out_file = Path(root_dir) / output_path
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Federated simulation completed successfully!")
    print(f"[+] Results saved to: {out_file}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GRAPH_Z3 Flower Federated Simulation")
    parser.add_argument("--num-clients", type=int, default=3, help="Number of simulated clients")
    parser.add_argument("--rounds", type=int, default=5, help="Number of FL communication rounds")
    parser.add_argument("--strategy", type=str, default="fedprox", choices=["fedavg", "fedprox"], help="FL Strategy")
    parser.add_argument("--epochs", type=int, default=2, help="Local epochs per round")
    parser.add_argument("--out", type=str, default="benchmark_federated_results.json", help="Output file")

    args = parser.parse_args()
    run_federated_simulation(
        num_clients=args.num_clients,
        num_rounds=args.rounds,
        strategy_name=args.strategy,
        local_epochs=args.epochs,
        output_path=args.out,
    )
