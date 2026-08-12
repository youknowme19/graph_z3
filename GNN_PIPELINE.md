# Graph Neural Network (GNN) Vulnerability Detection Pipeline

This document outlines the design, architecture, and step-by-step implementation guide for integrating a Graph Neural Network (GNN) into the Symbolic Execution & Z3 constraint solver pipeline.

---

## 1. Architectural Role: Why GNN + Symbolic Execution?

Symbolic execution using Z3 is mathematically sound and highly precise (generating exact exploit bytes), but it suffers from **path explosion** and is **computationally heavy/slow** on large binaries. 

A GNN solves this by learning to identify vulnerable graph structures (basic blocks) purely from the Control Flow Graph (CFG).

### The Dual-Mode Execution Flow
```
                         [ Unseen Binary ]
                                │
                                ▼
                       Extract angr CFG
                                │
                                ├─────────────────────────┐
                                ▼ (Fast Path)             ▼ (Precise Path)
                        Run GNN Inference                 Z3 Symbolic Exec
                                │                         (Slow, exhaustive)
                                ▼                         │
                        Predict Vuln Blocks               │
                                │                         │
                                ▼                         ▼
                     [ Candidate Blocks ] <─────── [ Generate Exploits ]
                                │
                                ▼
                       Z3 Solver Focus
                 (Only solve candidate paths)
```

1. **GNN Mode (Pre-Filter):** The GNN predicts which basic blocks are likely to contain vulnerabilities in **under 1 second**.
2. **Z3 Mode (Exploit Generator):** Symbolic execution is target-focused, running *only* on the paths leading to the blocks flagged by the GNN. This avoids path explosion.

---

## 2. Training Data Strategy: Labeled Data & Self-Labeling

To build a high-quality GNN model, we recommend a **hybrid dataset strategy**:

### Step 1: Download Labeled Datasets
1. **Juliet Test Suite for C/C++ (NIST SAMATE):**
   - **What it is:** A collection of over 64,000 synthetic test cases covering 118 different CWEs (Common Weakness Enumerations) like stack buffer overflows (CWE-121), divide-by-zero (CWE-369), etc.
   - **How to get it:** Download from [NIST SAMATE Juliet Suite](https://samate.nist.gov/SRD/testsuite.php).
   - **Labeling:** Each file has a clear `bad()` function (vulnerable) and several `good()` functions (patched/safe).

2. **Draper VDISC Dataset:**
   - **What it is:** A dataset of 1.2 million function-level control flow graphs and source code blocks labeled for vulnerabilities.

### Step 2: Self-Labeling Generator
You can compile these test suites with gcc/clang, and then run our Z3 solver tool on them in batch mode. The Z3 tool will output a JSON label for each basic block:
- `label = 1` if `state.is_vulnerable` is True.
- `label = 0` if the block was successfully explored but no vulnerability was triggered.

This builds a highly customized training dataset matched exactly to your tool's detection logic.

---

## 3. CFG Node Feature Vector Representation

Each node (basic block) in the GNN input graph is represented by a feature vector $X_i \in \mathbb{R}^d$. We extract these features using angr's VEX IR and symbolic state information:

```python
node_features = [
    # ── Structural/Topological Features ──
    in_degree,                  # Number of incoming jump edges
    out_degree,                 # Number of outgoing jump branches
    depth_from_entry,           # Distance in blocks from entry point
    is_loop_header,             # 1.0 if block is head of a loop, 0.0 otherwise
    is_library_call,            # 1.0 if block points to PLT/SimProcedure, 0.0 otherwise
    
    # ── Instruction-Level Features ──
    num_instructions,           # Count of assembly/IR instructions in block
    has_unsafe_call,            # 1.0 if contains string ops (strcpy, sprintf, etc.)
    has_memory_write,           # 1.0 if VEX contains store statements (Ist_Store)
    
    # ── Symbolic Execution Features (from Z3/angr state) ──
    num_symbolic_variables,     # Count of symbolic variables active in this block
    num_path_constraints,       # Count of path conditions accumulated to reach here
    has_symbolic_store_addr,    # 1.0 if memory write destination is symbolic
]
```

---

## 4. GNN Model Architecture (PyTorch Geometric)

We recommend using **GraphSAGE** (Graph Sample and Aggregate) or a **GAT** (Graph Attention Network) because they generalize well to unseen graph structures (inductive learning).

### Python Code Scaffold (`gnn_model.py`)
```python
import torch
import torch.nn.functional as F
from torch_geometric.nn import SAGEConv, global_mean_pool

class VulnGNN(torch.nn.Module):
    def __init__(self, input_dim, hidden_dim=64):
        super(VulnGNN, self).__init__()
        # GraphSAGE layers
        self.conv1 = SAGEConv(input_dim, hidden_dim)
        self.conv2 = SAGEConv(hidden_dim, hidden_dim)
        
        # Classification head for each block (Node Classification)
        self.classifier = torch.nn.Linear(hidden_dim, 2)  # [0: Safe, 1: Vulnerable]

    def forward(self, x, edge_index, batch=None):
        # 1. Graph Convolution
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = F.dropout(x, p=0.2, training=self.training)
        
        x = self.conv2(x, edge_index)
        x = F.relu(x)
        
        # 2. Block-level classification
        logits = self.classifier(x)
        return logits
```

---

## 5. Implementation Roadmap: Next Steps

To implement this pipeline in the future:
1. **Feature Extractor:** Write `src/graph/feature_extractor.py` to compile the `node_features` array for every basic block in the `GraphBuilder`.
2. **Dataset Builder:** Write `src/ml/dataset_builder.py` to parse CFG files and Z3 reports, saving them as `.pt` graph objects in PyTorch Geometric format (`torch_geometric.data.Data`).
3. **Training Loop:** Write `src/ml/trainer.py` to train `VulnGNN` using Binary Cross-Entropy Loss on labeled node targets.
4. **Model Integration:** Load the trained model (`model.pt`) into the Dash app. When a binary is uploaded, render the GNN vulnerability heatmap overlay on the CFG immediately, before symbolic execution finishes.
