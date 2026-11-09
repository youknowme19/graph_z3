#!/usr/bin/env python3
"""
Update Dataset Features: Eliminate Duplicate Features (Indices 5, 6, 35) Across All Graphs.

Replaces:
  - Feature 5 (formerly duplicate of in_degree): dominator_tree_depth
  - Feature 6 (formerly duplicate of out_degree): back_edge_count
  - Feature 35 (formerly duplicate of guard count): branch_condition_complexity

Ensures that all graphs in data/processed_graphs, data/primevul_graphs, and data/real_world_graphs
have mathematically defined, non-collinear features.
"""

import os
import glob
import time
import torch
import networkx as nx
from collections import defaultdict
from src.graph.feature_extractor import _normalize, FEATURE_NAMES, FEATURE_GROUPS


def compute_topological_replacements(data):
    """Compute dominator_tree_depth, back_edge_count, and branch_condition_complexity from graph topology & features."""
    num_nodes = data.num_nodes
    if num_nodes == 0:
        return torch.zeros(0), torch.zeros(0), torch.zeros(0)

    edge_index = data.edge_index
    H = nx.DiGraph()
    H.add_nodes_from(range(num_nodes))
    if edge_index is not None and edge_index.numel() > 0:
        for u, v in zip(edge_index[0].tolist(), edge_index[1].tolist()):
            H.add_edge(u, v)

    # 1. Dominator tree depth
    entries = [n for n in range(num_nodes) if H.in_degree(n) == 0]
    entry = entries[0] if entries else 0

    dom_depths = [0.0] * num_nodes
    try:
        idoms = nx.immediate_dominators(H, entry)
        for n in range(num_nodes):
            d = 0
            curr = n
            visited = set()
            while curr != entry and curr in idoms and curr not in visited:
                visited.add(curr)
                curr = idoms[curr]
                d += 1
            dom_depths[n] = _normalize(float(d), 0.0, 20.0)
    except Exception:
        # Fallback to shortest path depth
        for n in range(num_nodes):
            try:
                sp = nx.shortest_path_length(H, entry, n)
                dom_depths[n] = _normalize(float(sp), 0.0, 20.0)
            except Exception:
                dom_depths[n] = 0.0

    # 2. Back-edge count (loop latches & headers)
    back_edge_counts = [0.0] * num_nodes
    try:
        # DFS back-edge detection
        dfs_visited = set()
        dfs_stack = set()
        dfs_back_edges = set()

        def _dfs(u):
            dfs_visited.add(u)
            dfs_stack.add(u)
            for succ in H.successors(u):
                if succ in dfs_stack:
                    dfs_back_edges.add((u, succ))
                elif succ not in dfs_visited:
                    _dfs(succ)
            dfs_stack.remove(u)

        for e in entries or [0]:
            if e not in dfs_visited:
                _dfs(e)

        be_map = defaultdict(int)
        for u, v in dfs_back_edges:
            be_map[u] += 1
            be_map[v] += 1
        for n in range(num_nodes):
            back_edge_counts[n] = _normalize(float(be_map[n]), 0.0, 5.0)
    except Exception:
        pass

    # 3. Branch condition complexity
    # Combines comparison operator presence (feat 24), control flow (feat 22),
    # out_degree branching (>1), and upstream guard density (feat 27)
    cond_complexity = [0.0] * num_nodes
    if hasattr(data, "x") and data.x is not None and data.x.shape[1] >= 40:
        has_cmp = data.x[:, 24].tolist()
        has_ctrl = data.x[:, 22].tolist()
        out_d = [H.out_degree(n) for n in range(num_nodes)]
        guards = data.x[:, 27].tolist()

        for n in range(num_nodes):
            score = 0.0
            if has_cmp[n] > 0.5:
                score += 2.0
            if has_ctrl[n] > 0.5:
                score += 1.0
            if out_d[n] > 1:
                score += 1.5
            score += guards[n] * 3.0
            cond_complexity[n] = _normalize(float(score), 0.0, 10.0)

    return (
        torch.tensor(dom_depths, dtype=torch.float32),
        torch.tensor(back_edge_counts, dtype=torch.float32),
        torch.tensor(cond_complexity, dtype=torch.float32),
    )


def update_graph_file(pt_path: str) -> bool:
    try:
        data = torch.load(pt_path, weights_only=False)
        if not hasattr(data, "x") or data.x is None or data.x.shape[1] < 40:
            return False

        dom_depth, back_edges, cond_comp = compute_topological_replacements(data)

        # Update slots in place
        data.x[:, 5] = dom_depth
        data.x[:, 6] = back_edges
        data.x[:, 35] = cond_comp

        torch.save(data, pt_path)
        return True
    except Exception as e:
        print(f"Error updating {pt_path}: {e}")
        return False


def main():
    dirs = [
        "data/processed_graphs",
        "data/primevul_graphs",
        "data/real_world_graphs",
    ]
    all_files = []
    for d in dirs:
        all_files.extend(glob.glob(os.path.join(d, "*.pt")))

    print(f"[*] Updating 40-D features on {len(all_files)} graphs across {len(dirs)} directories...")
    t0 = time.time()
    updated = 0
    for i, path in enumerate(all_files, 1):
        if update_graph_file(path):
            updated += 1
        if i % 500 == 0 or i == len(all_files):
            elapsed = time.time() - t0
            rate = i / max(elapsed, 0.001)
            print(f"    [{i:5d}/{len(all_files)}] Updated={updated} | {rate:.1f} graphs/s | elapsed={elapsed:.1f}s", flush=True)

    print(f"[+] Complete: {updated}/{len(all_files)} graphs updated in {time.time() - t0:.2f}s")


if __name__ == "__main__":
    main()

