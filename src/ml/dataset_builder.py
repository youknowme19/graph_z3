import os
import sys
import networkx as nx
import json
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
    from torch_geometric.data import Data
except ImportError:
    # Fallback to avoid syntax errors if torch/PyG not installed yet
    torch = None
    Data = None

from src.core.interfaces import AnalysisBackendProvider
from src.graph.graph_builder import GraphBuilder
from src.graph.feature_extractor import FEATURE_NAMES


def build_graph_data(binary_path, max_steps=300, include_metadata=True):
    """
    Analyzes a binary, extracts its CFG and execution trace, and constructs
    a PyTorch Geometric Data object with node features and vulnerability labels.
    
    Args:
        binary_path: Path to the binary file
        max_steps: Maximum symbolic execution steps
        include_metadata: Whether to include CWE/type metadata in the graph
    
    Returns:
        PyG Data object or None if failed
    """
    if torch is None or Data is None:
        raise ImportError("PyTorch and PyTorch Geometric must be installed to run dataset builder.")

    binary_name = os.path.basename(binary_path)
    print(f"[+] Scanning binary: {binary_name}")
    
    # 1. Run symbolic execution scan to find vulnerable basic blocks
    backend = AnalysisBackendProvider(binary_path, max_steps=max_steps)
    
    try:
        trace = backend.get_execution_trace()
    except Exception as e:
        print(f"[-] Error getting execution trace: {e}")
        trace = []

    # Collect addresses of basic blocks flagged as vulnerable
    vuln_addresses = set()
    vuln_details = {}  # addr -> details dict
    for state in trace:
        if state.is_vulnerable:
            try:
                addr_int = int(state.basic_block, 16)
                vuln_addresses.add(addr_int)
                vuln_details[addr_int] = {
                    'vuln_type': state.vuln_type,
                    'vuln_severity': state.vuln_severity,
                    'vuln_details': state.vuln_details,
                }
            except Exception:
                pass

    # 2. Build the NetworkX CFG with feature vectors
    builder = GraphBuilder(backend.loader)
    nx_cfg = builder.build_networkx_cfg()

    if not nx_cfg or len(nx_cfg.nodes()) == 0:
        print(f"[-] Warning: Empty CFG for {binary_name}")
        return None

    # 3. Map NetworkX nodes (addresses) to sequential indices for PyG
    nodes = list(nx_cfg.nodes())
    node_to_idx = {node_addr: idx for idx, node_addr in enumerate(nodes)}

    # 4. Construct Feature Matrix (X) and Labels (Y)
    x_list = []
    y_list = []
    node_metadata = []  # per-node metadata for debugging

    for node_addr in nodes:
        node_data = nx_cfg.nodes[node_addr]
        
        # Extract features (now 40-dimensional)
        features = node_data.get('features', [0.0] * len(FEATURE_NAMES))
        
        # Sanity check: feature dimension should match
        if len(features) != len(FEATURE_NAMES):
            # Pad or truncate
            if len(features) < len(FEATURE_NAMES):
                features = features + [0.0] * (len(FEATURE_NAMES) - len(features))
            else:
                features = features[:len(FEATURE_NAMES)]
        
        x_list.append(features)
        
        # Label: 1 if this block was flagged as vulnerable, otherwise 0
        label = 1 if node_addr in vuln_addresses else 0
        y_list.append(label)
        
        # Store metadata
        node_metadata.append({
            'addr': hex(node_addr),
            'name': node_data.get('name', f'sub_{hex(node_addr)}'),
            'label': label,
            'vuln_type': vuln_details.get(node_addr, {}).get('vuln_type', ''),
            'vuln_severity': vuln_details.get(node_addr, {}).get('vuln_severity', ''),
        })

    x = torch.tensor(x_list, dtype=torch.float)
    y = torch.tensor(y_list, dtype=torch.long)

    # 5. Construct Edge Index (COO Format)
    edge_sources = []
    edge_targets = []
    for src, dst in nx_cfg.edges():
        if src in node_to_idx and dst in node_to_idx:
            edge_sources.append(node_to_idx[src])
            edge_targets.append(node_to_idx[dst])

    if edge_sources:
        edge_index = torch.tensor([edge_sources, edge_targets], dtype=torch.long)
    else:
        edge_index = torch.empty((2, 0), dtype=torch.long)

    # 6. Create PyG Data object
    data = Data(x=x, edge_index=edge_index, y=y)
    
    # Save the address mapping and metadata
    data.node_addrs = torch.tensor(nodes, dtype=torch.long)
    data.node_metadata = node_metadata
    data.binary_name = binary_name
    data.binary_path = binary_path
    
    # Add CWE/category info if available from filename
    cwe = None
    for part in binary_name.split('_'):
        if part.startswith('CWE') and part[3:].isdigit():
            cwe = part
            break
    data.cwe = cwe
    
    vuln_count = sum(y_list)
    print(f"[+] Graph built: {len(nodes)} nodes, {len(edge_sources)} edges, {vuln_count} vulnerable blocks")
    
    return data


def build_dataset(binaries_dir, output_dir, max_steps=300, max_binaries=None):
    """
    Processes all binaries in the binaries_dir, generates PyG Data objects,
    and saves them in output_dir.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    binaries_dir = Path(binaries_dir)
    output_dir = Path(output_dir)
    
    # Find all binary files
    binaries = []
    for ext in ['.out', '.elf', '.exe', '']:
        binaries.extend(binaries_dir.glob(f'*{ext}'))
    
    # Filter out non-binaries (source files, scripts, etc.)
    binaries = [
        f for f in binaries 
        if f.is_file() and not f.name.endswith(('.py', '.txt', '.c', '.h', '.cpp', '.cc', '.json', '.md'))
    ]
    
    if max_binaries:
        binaries = binaries[:max_binaries]

    print(f"[+] Found {len(binaries)} candidate binaries in {binaries_dir}")

    success_count = 0
    failed = []
    stats = {
        'total_nodes': 0,
        'total_edges': 0,
        'total_vuln': 0,
        'per_cwe': {}
    }

    for binary_path in binaries:
        try:
            data = build_graph_data(str(binary_path), max_steps=max_steps)
            if data is not None:
                output_path = output_dir / f"{binary_path.name}.pt"
                torch.save(data, output_path)
                print(f"[+] Successfully saved graph to {output_path}")
                
                # Update stats
                stats['total_nodes'] += data.num_nodes
                stats['total_edges'] += data.num_edges
                vuln_count = int(data.y.sum())
                stats['total_vuln'] += vuln_count
                
                if data.cwe:
                    if data.cwe not in stats['per_cwe']:
                        stats['per_cwe'][data.cwe] = {'graphs': 0, 'vuln': 0, 'nodes': 0}
                    stats['per_cwe'][data.cwe]['graphs'] += 1
                    stats['per_cwe'][data.cwe]['vuln'] += vuln_count
                    stats['per_cwe'][data.cwe]['nodes'] += data.num_nodes
                
                success_count += 1
        except Exception as e:
            print(f"[-] Failed to process {binary_path.name}: {e}")
            failed.append((binary_path.name, str(e)))

    # Save dataset statistics
    stats_path = output_dir / "dataset_stats.json"
    with open(stats_path, 'w') as f:
        json.dump(stats, f, indent=2)
    
    print(f"\n[+] Dataset construction finished.")
    print(f"    Successful: {success_count}/{len(binaries)}")
    print(f"    Total nodes: {stats['total_nodes']}")
    print(f"    Total edges: {stats['total_edges']}")
    print(f"    Total vulnerable blocks: {stats['total_vuln']}")
    print(f"    Vulnerability rate: {stats['total_vuln'] / max(stats['total_nodes'], 1) * 100:.2f}%")
    print(f"    Stats saved to {stats_path}")
    
    if failed:
        print(f"\n[!] Failed ({len(failed)}):")
        for name, err in failed:
            print(f"    {name}: {err}")
    
    return success_count, stats


def analyze_dataset(dataset_dir):
    """Analyze an existing dataset and print statistics."""
    dataset_dir = Path(dataset_dir)
    pt_files = list(dataset_dir.glob("*.pt"))
    
    if not pt_files:
        print("[-] No .pt files found")
        return
    
    print(f"[+] Analyzing {len(pt_files)} graphs...")
    
    total_nodes = 0
    total_edges = 0
    total_vuln = 0
    per_cwe = {}
    
    for file_path in pt_files:
        try:
            data = torch.load(file_path, weights_only=False)
            total_nodes += data.num_nodes
            total_edges += data.num_edges
            vuln = int(data.y.sum())
            total_vuln += vuln
            
            if hasattr(data, 'cwe') and data.cwe:
                if data.cwe not in per_cwe:
                    per_cwe[data.cwe] = {'graphs': 0, 'vuln': 0, 'nodes': 0}
                per_cwe[data.cwe]['graphs'] += 1
                per_cwe[data.cwe]['vuln'] += vuln
                per_cwe[data.cwe]['nodes'] += data.num_nodes
        except Exception as e:
            print(f"[-] Error loading {file_path}: {e}")
    
    print(f"\n=== Dataset Statistics ===")
    print(f"Graphs: {len(pt_files)}")
    print(f"Total nodes: {total_nodes}")
    print(f"Total edges: {total_edges}")
    print(f"Total vulnerable blocks: {total_vuln}")
    print(f"Vulnerability rate: {total_vuln / max(total_nodes, 1) * 100:.2f}%")
    print(f"Avg nodes per graph: {total_nodes / max(len(pt_files), 1):.1f}")
    print(f"Avg edges per graph: {total_edges / max(len(pt_files), 1):.1f}")
    
    if per_cwe:
        print(f"\nPer-CWE breakdown:")
        for cwe, stats in sorted(per_cwe.items()):
            print(f"  {cwe}: {stats['graphs']} graphs, {stats['nodes']} nodes, {stats['vuln']} vuln blocks "
                  f"({stats['vuln'] / max(stats['nodes'], 1) * 100:.2f}%)")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Build PyTorch Geometric dataset from binary CFGs and Z3 execution traces.")
    parser.add_argument("--binaries-dir", type=str, required=True, help="Directory containing compiled binaries")
    parser.add_argument("--output-dir", type=str, required=True, help="Directory to save the PyG .pt graphs")
    parser.add_argument("--max-steps", type=int, default=300, help="Max steps for symbolic analysis execution trace")
    parser.add_argument("--max-binaries", type=int, help="Limit number of binaries to process")
    parser.add_argument("--analyze", action="store_true", help="Analyze existing dataset instead of building")
    
    args = parser.parse_args()
    
    if args.analyze:
        analyze_dataset(args.binaries_dir)
    else:
        build_dataset(args.binaries_dir, args.output_dir, args.max_steps, args.max_binaries)