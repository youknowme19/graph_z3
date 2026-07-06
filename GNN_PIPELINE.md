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

