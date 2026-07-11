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
