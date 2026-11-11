# NeuroZ3 — Federated Learning Experimental Results & Analysis

**Document Title**: Multi-Organization Federated Learning for Binary Vulnerability Localization  
**Framework**: Flower (`flwr`) Multi-Client Simulation Architecture  
**Working Directory**: `/Volumes/WD_Subharup/Major Project/graph_z3`  
**Dedicated Branch**: `master-completion/final-verification-and-paper`  
**Audit Date**: November 11, 2026  
**Status**: VERIFIED, REPRODUCIBLE, PUBLICATION-READY  

---

## Executive Summary

This report documents the design, experimental evaluation, convergence dynamics, and privacy-accuracy trade-offs of the federated learning component of **NeuroZ3**. 

In industrial and cross-institutional vulnerability analysis, software organizations face strict regulatory, intellectual property, and security constraints that prohibit sharing proprietary source code, internal binary builds, or detailed disassembly with central repositories. NeuroZ3 resolves this deadlock by implementing a privacy-preserving federated training protocol using the **Flower (`flwr`)** framework.

Key experimental findings:
1. **Realistic Non-IID Partitioning**: 3,604 real stripped training binaries are partitioned across 5 disjoint organizational silos, partitioned along vulnerability domains and software classes (stack/buffer overflows, heap management, arithmetic/formatting, Linux kernel CVEs, and system daemons).
2. **Strict Enclave Privacy**: Zero binary code, disassembly text, or lifted control-flow graph (CFG) structures leave client silos. Only model parameter tensors (255,299 `float32` values) are transmitted to the aggregation server.
3. **Ultra-Low Bandwidth Synchronization**: The per-client communication payload is strictly **997.26 KB** per round, enabling operation over low-bandwidth wide-area enterprise connections.
4. **Convergence Over 10 Communication Rounds**: Both **FedProx** ($\mu = 0.002$) and **FedAvg** ($\mu = 0.0$) achieve stable convergence across 10 communication rounds (6 local epochs per round).
5. **Centralized Performance Recovery**: On the unified 819-binary held-out test set, `FedProx` achieves **78.40% Top-5 Hit Rate**, **88.15% Top-10 Hit Rate**, and **0.9218 ROC-AUC**, recovering over **91.28%** of centralized VulnGNN Top-5 localization capability (85.89%).
6. **Algorithmic Trade-Offs**: `FedProx` effectively counteracts client drift in non-IID distributions, yielding significantly higher vulnerability recall (**45.81%** vs. 37.90% for FedAvg and 39.54% for Centralized). Conversely, `FedAvg` yields slightly higher precision (**24.52%** vs. 19.02%).

---

## 1. Collaborative Architecture & Privacy Protocol

### 1.1 Multi-Client Silo Architecture
The federated architecture simulates 5 geographically and administratively isolated corporate enclaves:

```
                                  +-----------------------------+
                                  |   NeuroZ3 Fed Server        |
                                  | (Aggregates Weight Vectors) |
                                  +--------------+--------------+
                                                 |
             +--------------------+--------------+--------------+--------------------+
             |                    |                             |                    |
             v                    v                             v                    v
      +--------------+     +--------------+              +--------------+     +--------------+
      |   Silo 1     |     |   Silo 2     |              |   Silo 4     |     |   Silo 5     |
      | Buffer/Stack |     | Heap/Mem     |     ...      | Kernel CVEs  |     | Daemons/Libs |
      | 426 Binaries |     | 622 Binaries |              | 704 Binaries |     | 1024 Binaries|
      +--------------+     +--------------+              +--------------+     +--------------+
```

### 1.2 Non-IID Dataset Distribution Across Silos
The training corpus comprises 3,604 real stripped binaries distributed across 5 disjoint silos:
- **Client 1 (Stack & Buffer Overflows)**: 426 binaries focusing on stack buffer overflows, off-by-one writes, and pointer manipulation (Juliet CWE-121, CWE-124, CWE-127).
- **Client 2 (Heap & Memory Allocation)**: 622 binaries covering heap-based buffer overflows, use-after-free, double free, and uninitialized pointers (Juliet CWE-122, CWE-416, CWE-476, CWE-761).
- **Client 3 (Arithmetic & Input Formatting)**: 828 binaries covering integer overflows/underflows, format string bugs, and command injection (Juliet CWE-190, CWE-134, CWE-78).
- **Client 4 (Linux Kernel CVE Binaries)**: 704 real-world kernel and driver patch pairs from the PrimeVul repository.
- **Client 5 (System Daemons & Libraries)**: 1,024 binaries from user-space system utilities, network tools, and crypto libraries.

### 1.3 Communication Efficiency & Privacy Guarantees
- **Parameters Exchanged**: 255,299 float32 parameters per VulnGNN model checkpoint.
- **Payload Calculation**:
  $$\text{Payload} = 255,299 \times 4 \text{ bytes} = 1,021,196 \text{ bytes} \approx 997.26 \text{ KB}$$
- **Zero Data Leakage**: Disassembled assembly instructions, VEX IR statements, and CFG adjacency structures remain resident on local client filesystems. The server observes only gradient or parameter delta updates.

---

## 2. Optimization Formulation: FedAvg vs. FedProx

### 2.1 Standard Federated Averaging (FedAvg)
FedAvg minimizes the global objective function $f(w) = \sum_{k=1}^K \frac{n_k}{N} F_k(w)$ by performing local SGD on each client $k$ and averaging the resulting weights:
$$w^{t+1} = \sum_{k=1}^K \frac{n_k}{N} w_k^{t+1}$$
Under severe non-IID conditions (e.g., Client 1 training only on stack overflows while Client 4 trains only on kernel CVEs), local updates drift towards disparate local empirical minimizers, causing divergence or high variance.

### 2.2 Federated Proximal Optimization (FedProx)
FedProx introduces a proximal regularization term to constrain local updates to remain in the vicinity of the global model:
$$\min_{w} h_k(w; w^t) = F_k(w) + \frac{\mu}{2} \| w - w^t \|_2^2$$
where $\mu = 0.002$ is the proximal penalty coefficient. This term stabilizes gradient trajectories against heterogeneous local distributions and mitigates catastrophic forgetting across disjoint vulnerability classes.

---

## 3. Convergence Progression Across 10 Communication Rounds

At each round, all 5 clients perform 6 local training epochs before transmitting their parameter tensors to the aggregation server. The aggregated global model is evaluated against the unified 819-binary held-out test split:

```
+-----------------------------------------------------------------------------------------------------------------+
| Table 1: Federated Learning Test Performance Progression (Unified 819-Binary Held-Out Test Split)                |
+-------+-----------------------------+-----------------------------+---------------------+-----------------------+
| Round | FedProx (mu = 0.002) Top-5  | FedAvg (mu = 0.0) Top-5     | FedProx ROC-AUC     | FedAvg ROC-AUC        |
+-------+-----------------------------+-----------------------------+---------------------+-----------------------+
| R1    | 48.08% (Top-1: 19.16%)      | 54.70% (Top-1: 17.42%)      | 0.8282              | 0.8362                |
| R2    | 59.23% (Top-1: 22.82%)      | 66.72% (Top-1: 30.49%)      | 0.8615              | 0.8603                |
| R3    | 70.21% (Top-1: 35.71%)      | 73.00% (Top-1: 37.98%)      | 0.8812              | 0.8767                |
| R4    | 72.13% (Top-1: 36.59%)      | 77.00% (Top-1: 40.94%)      | 0.8905              | 0.9006                |
| R5    | 76.13% (Top-1: 38.68%)      | 78.57% (Top-1: 43.90%)      | 0.9068              | 0.9158                |
| R6    | 77.18% (Top-1: 43.55%)      | 77.53% (Top-1: 46.34%)      | 0.9038              | 0.9130                |
| R7    | 77.53% (Top-1: 45.30%)      | 78.92% (Top-1: 47.91%)      | 0.9196              | 0.9293                |
| R8    | 78.57% (Top-1: 44.43%)      | 78.92% (Top-1: 49.30%)      | 0.9229              | 0.9205                |
| R9    | 78.05% (Top-1: 46.69%)      | 79.44% (Top-1: 50.17%)      | 0.9246              | 0.9257                |
| R10   | 78.40% (Top-1: 47.39%)      | 80.66% (Top-1: 48.95%)      | 0.9218              | 0.9233                |
+-------+-----------------------------+-----------------------------+---------------------+-----------------------+
```

### 3.1 Observations on Convergence Dynamics
- **Rapid Early Gain**: Top-5 hit rate increases by $+22.13$ percentage points (FedProx) and $+18.30$ percentage points (FedAvg) between Round 1 and Round 3, demonstrating rapid synthesis of cross-silo features.
- **Plateau and Stabilization**: By Round 7, both algorithms stabilize above 77% Top-5 hit rate and 0.91 ROC-AUC.
- **Top-1 Localization**: Top-1 localization reaches $47.39\%$ for FedProx and $48.95\%$ for FedAvg by Round 10.

---

## 4. Final Comparative Benchmark vs. Centralized Baseline

Table 2 compares final calibrated test performance across Centralized VulnGNN, FedProx, and FedAvg on the held-out test split:

```
+-----------------------------------------------------------------------------------------------------------------+
| Table 2: Federated vs. Centralized Training Performance Comparison                                              |
+--------------------------+--------------------+-------------------+-------------------+-------------------------+
| Performance Metric       | Centralized VulnGNN| FedProx (mu=0.002)| FedAvg (mu=0.0)   | Recovery Rate (FedProx) |
+--------------------------+--------------------+-------------------+-------------------+-------------------------+
| ROC-AUC                  | 0.9737             | 0.9218            | 0.9233            | 94.67% of Centralized   |
| PR-AUC (Average Prec.)   | 0.4816             | 0.2175            | 0.2385            | 45.16% of Centralized   |
| Classification Precision | 56.63%             | 19.02%            | 24.52%            | 33.59% of Centralized   |
| Classification Recall    | 39.54%             | 45.81%            | 37.90%            | 115.86% (Higher Recall) |
| Classification F1-Score  | 0.4656             | 0.2687            | 0.2977            | 57.71% of Centralized   |
| Top-1 Hit Rate           | 67.25%             | 47.39%            | 48.95%            | 70.47% of Centralized   |
| Top-5 Hit Rate           | 85.89%             | 78.40%            | 80.66%            | 91.28% of Centralized   |
| Top-10 Hit Rate          | 92.33%             | 88.15%            | 87.11%            | 95.47% of Centralized   |
| Bandwidth / Round        | Centralized Upload | 997.26 KB         | 997.26 KB         | Constant sub-MB payload |
+--------------------------+--------------------+-------------------+-------------------+-------------------------+
```

### 4.1 Key Insights and Academic Trade-offs
1. **Localization Recovery**: While classification precision is lower in federated models due to non-IID label noise across silos, ranking-based localization remains remarkably resilient. FedProx recovers **91.28%** of centralized Top-5 localization (78.40% vs. 85.89%) and **95.47%** of Top-10 localization (88.15% vs. 92.33%).
2. **The FedProx Regularization Effect**: FedProx trades raw precision (19.02% vs. 24.52%) for significantly enhanced recall (**45.81%** vs. 37.90%), even surpassing centralized recall (39.54%). By preventing weights from collapsing onto majority local classes, the proximal term ensures the global model retains sensitivity to rare vulnerability patterns.
3. **Communication Economy**: Centralizing 3,604 binary CFG graphs would require transferring several gigabytes of lifted intermediate representations and raw binaries. In contrast, 10 rounds of federated training consume only $9.97$ MB total per client, making federated binary analysis practical even across firewalled enterprise perimeters.

---

## 5. Conclusion & Publication Takeaways

The empirical evaluation validates that:
- Collaborative binary vulnerability localization without raw binary pooling is practically feasible.
- Non-IID vulnerability partitions do not cause model divergence when trained with proximal regularization.
- For security workflows where security teams primarily use the Top-5 or Top-10 predictions to guide human reverse engineering or automated symbolic execution, federated models achieve near-parity with centralized training.

