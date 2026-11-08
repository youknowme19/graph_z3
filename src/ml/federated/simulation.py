"""
End-to-End Federated Learning Simulation for NeuroZ3 (GRAPH_Z3) using Flower.

Simulates multiple independent security organizations collaborating to train
40-dimensional Bidirectional VulnGNN under Non-IID vulnerability and repository silos
strictly over real compiled stripped binary CFGs.

Usage:
    python -m src.ml.federated.simulation --num-clients 5 --rounds 10 --strategy fedprox
"""

import os
import sys
import argparse
import json
from pathlib import Path
from typing import Dict, List, Any

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    import torch
except ImportError:
    torch = None

try:
    from torch_geometric.loader import DataLoader
except ImportError:
    DataLoader = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import flwr as fl
    FLWR_AVAILABLE = True
except ImportError:
    FLWR_AVAILABLE = False

from src.ml.federated.client import FlowerVulnClient, create_client
from src.ml.federated.server import (
    create_federated_strategy,
    get_initial_parameters,
    aggregate_fit_metrics,
    aggregate_eval_metrics,
)
from src.ml.trainer import load_pt_dataset, _extract_cwe, _split_by_binary


def partition_dataset_non_iid(
    dataset: List[Any], num_clients: int = 5
) -> List[List[Any]]:
    """
    Partitions real binary CFG graphs across clients in a Non-IID fashion:
      - When num_clients == 5, assigns the 5 canonical organizational silos:
          Silo 0: Stack & Out-of-Bounds Memory Safety (CWE-121/124/126/127)
          Silo 1: Heap & Pointer Lifecycle (CWE-122/415/416/476/590/690/761/789)
          Silo 2: Arithmetic & Input-Taint (CWE-190/191/194/195/197/680/134/78/369)
          Silo 3: Linux Kernel Real-World CVEs (PrimeVul linux repository)
          Silo 4: User-Space OSS Daemons & Libraries Real-World CVEs (openssl, FFmpeg, etc.)
      - For arbitrary num_clients, maps each canonical silo modulo num_clients.
    """
    silos: List[List[Any]] = [[] for _ in range(5)]
    for d in dataset:
        cwe = _extract_cwe(d)
        src = str(getattr(d, "corpus_source", ""))
        proj = str(getattr(d, "project", "")).lower()
        if src == "primevul_real_cve":
            if proj == "linux":
                silos[3].append(d)
            else:
                silos[4].append(d)
        elif cwe in ("CWE121", "CWE124", "CWE126", "CWE127"):
            silos[0].append(d)
        elif cwe in ("CWE122", "CWE415", "CWE416", "CWE476", "CWE590", "CWE690", "CWE761", "CWE789"):
            silos[1].append(d)
        else:
            silos[2].append(d)

    if num_clients == 5:
        return silos

    clients_data: List[List[Any]] = [[] for _ in range(num_clients)]
    for s_idx, silo_items in enumerate(silos):
        for item_idx, item in enumerate(silo_items):
            target_c = (s_idx if num_clients <= 5 else (s_idx + item_idx)) % num_clients
            clients_data[target_c].append(item)

    for c_i in range(num_clients):
        if not clients_data[c_i] and dataset:
            clients_data[c_i].append(dataset[c_i % len(dataset)])
    return clients_data


def run_federated_simulation(
    num_clients: int = 5,
    num_rounds: int = 10,
    strategy_name: str = "fedprox",
    local_epochs: int = 6,
    proximal_mu: float = 0.002,
    dataset_dir: str = "",
    output_path: str = "benchmark_federated_results.json",
):
    """Executes the Flower federated learning simulation exclusively on real binary CFG graphs."""
    if not FLWR_AVAILABLE:
        print("[-] Flower (flwr) is not installed. To run this simulation, install:")
        print("    pip install 'flwr>=1.7.0'")
        return

    print("==================================================")
    print("  NeuroZ3 Federated Learning Simulation (Flower)  ")
    print("==================================================")
    print(f"[*] Participating Clients : {num_clients}")
    print(f"[*] Aggregation Rounds    : {num_rounds}")
    print(f"[*] Strategy              : {strategy_name.upper()} (mu={proximal_mu if strategy_name=='fedprox' else 0.0})")
    print(f"[*] Local Epochs / Round  : {local_epochs}")
    print("==================================================")

    target_dirs = []
    if dataset_dir:
        target_dirs.append(dataset_dir)
    else:
        for sub in ("primevul_graphs", "processed_graphs"):
            cand = os.path.join(root_dir, "data", sub)
            if os.path.isdir(cand):
                target_dirs.append(cand)

    graphs = load_pt_dataset(target_dirs)
    if not graphs:
        raise RuntimeError(
            "No real .pt binary CFG graphs found! Refusing to generate synthetic graphs. "
            "Build the real binary corpus first via scripts/build_primevul_real_corpus.py or scripts/build_large_corpus.py."
        )

    feat_dim = int(graphs[0].x.shape[1])
    print(f"[+] Total real binary CFG graphs loaded: {len(graphs)} (feature dim={feat_dim})")

    client_partitions = partition_dataset_non_iid(graphs, num_clients)
    client_splits = []
    for c_id, part in enumerate(client_partitions):
        tr, va, _ = _split_by_binary(part, train_ratio=0.80, val_ratio=0.20, test_ratio=0.0, seed=42 + c_id)
        if not va:
            va = tr[-max(1, len(tr) // 5):]
        client_splits.append((tr, va))
        print(f"[+] Client {c_id}: {len(part)} real binary graphs assigned (train={len(tr)}, val={len(va)})")

    eff_mu = proximal_mu if strategy_name.lower() == "fedprox" else 0.0

    def client_fn(cid: str) -> FlowerVulnClient:
        client_idx = int(cid)
        train_data, val_data = client_splits[client_idx]
        train_loader = DataLoader(train_data, batch_size=32, shuffle=True)
        val_loader = DataLoader(val_data, batch_size=32, shuffle=False)

        return create_client(
            client_id=f"client_{client_idx}",
            train_loader=train_loader,
            val_loader=val_loader,
            input_dim=feat_dim,
            hidden_dim=128,
            num_layers=3,
            encoder="sage",
            local_epochs=local_epochs,
            proximal_mu=eff_mu,
        )

    print("[*] Starting Flower federated orchestration...")
    clients = [client_fn(str(i)) for i in range(num_clients)]
    global_params = clients[0].get_parameters(config={})

    losses_distributed = []
    metrics_distributed: Dict[str, List[float]] = {}

    for rnd in range(1, num_rounds + 1):
        fit_Outputs = []
        total_train_examples = 0
        fit_metrics_list = []

        for c in clients:
            updated_w, n_ex, f_metrics = c.fit(
                global_params,
                config={"server_round": rnd, "local_epochs": local_epochs, "proximal_mu": eff_mu},
            )
            fit_Outputs.append((updated_w, n_ex))
            total_train_examples += n_ex
            fit_metrics_list.append((n_ex, f_metrics))

        # Sample-weighted FedAvg / FedProx server aggregation
        global_params = [
            sum(w_client[layer_idx] * (n_ex / max(total_train_examples, 1)) for w_client, n_ex in fit_Outputs)
            for layer_idx in range(len(global_params))
        ]
        agg_fit = aggregate_fit_metrics(fit_metrics_list)

        eval_metrics_list = []
        total_val_examples = 0
        weighted_val_loss = 0.0
        for c in clients:
            v_loss, n_val, e_metrics = c.evaluate(global_params, config={"server_round": rnd})
            eval_metrics_list.append((n_val, e_metrics))
            total_val_examples += n_val
            weighted_val_loss += v_loss * n_val

        agg_eval = aggregate_eval_metrics(eval_metrics_list)
        round_loss = weighted_val_loss / max(total_val_examples, 1)
        losses_distributed.append(float(round_loss))
        for k, v in agg_eval.items():
            metrics_distributed.setdefault(k, []).append(float(v))

        print(
            f"  [Round {rnd:02d}/{num_rounds:02d}] "
            f"train_loss={agg_fit.get('train_loss', 0.0):.4f} | "
            f"val_loss={round_loss:.4f} | "
            f"roc_auc={agg_eval.get('roc_auc', 0.0):.4f} | "
            f"top1={agg_eval.get('top1_hit_rate', 0.0)*100:.2f}% | "
            f"top5={agg_eval.get('top5_hit_rate', 0.0)*100:.2f}%"
        )

    results = {
        "num_clients": num_clients,
        "rounds": num_rounds,
        "strategy": strategy_name,
        "proximal_mu": eff_mu,
        "local_epochs": local_epochs,
        "client_partition_sizes": [len(p) for p in client_partitions],
        "losses_distributed": losses_distributed,
        "metrics_distributed": metrics_distributed,
    }

    out_file = Path(root_dir) / output_path
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Federated simulation completed successfully!")
    print(f"[+] Results saved to: {out_file}")
    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NeuroZ3 Flower Federated Simulation")
    parser.add_argument("--num-clients", type=int, default=5, help="Number of simulated clients")
    parser.add_argument("--rounds", type=int, default=10, help="Number of FL communication rounds")
    parser.add_argument("--strategy", type=str, default="fedprox", choices=["fedavg", "fedprox"], help="FL Strategy")
    parser.add_argument("--epochs", type=int, default=6, help="Local epochs per round")
    parser.add_argument("--mu", type=float, default=0.002, help="FedProx proximal weight mu")
    parser.add_argument("--out", type=str, default="benchmark_federated_results.json", help="Output file")

    args = parser.parse_args()
    run_federated_simulation(
        num_clients=args.num_clients,
        num_rounds=args.rounds,
        strategy_name=args.strategy,
        local_epochs=args.epochs,
        proximal_mu=args.mu,
        output_path=args.out,
    )
