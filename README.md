# Neuro-Symbolic Fuzzer - Educational Module

An educational Binary Analysis and Symbolic Verification platform.
Demonstrates Control Flow Graph (CFG) extraction, Call Graph generation, and step-by-step symbolic execution using `angr` and `z3`.

## Features
- Ghidra-style interactive graph visualization using Dash and Cytoscape.
- Step-by-step symbolic execution trace.
- Z3 constraint extraction and educational plain-English explanations.
- Rich node metadata for future Graph Neural Network (GNN) integration.

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
python main.py path/to/binary
```

## Landing Page
The landing page (`/`) features a MetaMask-inspired parallax storytelling design:
- Full-screen hero with scroll-driven opacity and floating holographic stickers
- Five sticky-pinned "Act" chapters driven by scroll progress
- Glowing gradient section dividers between each chapter
- Act I: Legacy vs GRAPH_Z3 side-by-side comparison
- Act II: Interactive 40-dim GNN CFG basic block explorer
- Act III: Live Z3 SMT-LIB2 formula viewer with animated solver steps
- Act IV: Exploit byte payload heatmap + copy-to-clipboard Python PoC
- Act V: Scroll-driven CWE diff viewer with automated fix advisories

## Design System
- **Typography**: Inter (headings) + JetBrains Mono (code/terminal)
- **Color palette**: Slate-950 base, Cyan/Teal accents, Purple/Pink for proofs, Amber for exploits
- **Animations**: float-gentle, float-tilt, float-orbit, hero-glow-pulse, fade-up, text-shimmer
- **Components**: HoloSticker (3D tilt), ParallaxCanvas (CFG particles), metamask-card (glassmorphism)

## Z3 Crash Payloads
When a vulnerability is confirmed SAT by Z3, the payload is available as:
1. **Decimal integer array** in the vulnerability card UI: `[32, 4, 4, 1, 1, 8, ...]`
2. **JSON export**: `crash_payload`, `crash_length`, `reproduce_cmd` fields
3. **Python reproducer**: `python3 -c "import sys; sys.stdout.buffer.write(bytes([...]))" | ./target.bin`

## CVSS Scoring
- **Peak CVSS**: Highest individual severity across all proved vulnerabilities
- **Average CVSS**: Mean score weighted by path reachability probability
- **Composite Risk Score**: 0.7 × Peak + 0.3 × Average
- **Risk Tiers**: LOW (0–3.9 / cyan), MEDIUM (4.0–6.4 / amber), HIGH (6.5–8.4 / orange), CRITICAL (8.5–10 / red)

## Supported Binary Formats
- ELF (x86-64, AArch64, ARM32)
- Mach-O (x86-64, ARM64 / Apple Silicon)
- PE (x86, x86-64)

## Mitigations Detected
PIE, NX, Stack Canary, FULL_RELRO, PARTIAL_RELRO, FORTIFY_SOURCE
