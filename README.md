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
