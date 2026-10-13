# NeuroZ3 Command Line Interface (CLI) Reference

## 1. Syntax Overview

```bash
python main.py [COMMAND | OPTIONS]
```

---

## 2. Options and Parameters

### Analysis & Scanning
- `--scan <PATH>`
  - Path to target compiled binary (ELF, PE, Mach-O).
  - Initiates headless neuro-symbolic analysis and SMT verification.
- `--output-json <PATH>`
  - File path to save complete structured JSON report.
- `--output-sarif <PATH>`
  - File path to save OASIS SARIF 2.1.0 standard report for CI/CD ingestion.
- `--max-steps <INT>`
  - Maximum symbolic execution exploration depth (Default: `300`).

### Web UI and REST API
- `--port <INT>`
  - Port for the web interface and REST API (Default: `8050`).
- `--host <IP>`
  - Host IP address to bind server (Default: `127.0.0.1`).
- `--dash`
  - Launches legacy Dash visualization server instead of primary React application.

### Federated Learning (Flower)
- `--federated`
  - Launches multi-client federated training simulation.
- `--fl-clients <INT>`
  - Number of participating federated enterprise nodes (Default: `3`).
- `--fl-rounds <INT>`
  - Number of communication and aggregation rounds (Default: `5`).
- `--fl-strategy <fedprox | fedavg>`
  - Aggregation strategy algorithm (Default: `fedprox`).

---

## 3. Exit Status Codes

| Exit Code | Meaning | Context |
| :--- | :--- | :--- |
| `0` | Analysis Clean | No vulnerabilities of `CRITICAL` or `HIGH` severity detected. |
| `1` | Vulnerability Confirmed | One or more verified high-severity vulnerabilities proven SAT by Z3. |
| `2` | Engine Error | Target binary unreadable or analysis backend exception encountered. |

---

## 4. Usage Examples

### Standard Headless Verification
```bash
python main.py --scan ./data/samples/cwe120_buffer_overflow \
               --output-json ./reports/report.json \
               --output-sarif ./reports/report.sarif
```

### Production Web Portal Launch
```bash
python main.py --host 0.0.0.0 --port 8050
```

### Federated Learning Benchmark
```bash
python main.py --federated --fl-clients 5 --fl-rounds 10 --fl-strategy fedprox
```
