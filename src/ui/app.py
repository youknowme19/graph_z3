"""
Neuro-Symbolic Fuzzer  ·  Professional RE Tool UI
app.py — Dash application factory.

Styled to feel like Ghidra / IDA Pro:
  - IDA-inspired theme with Dark/Light mode toggle utilizing CSS variables
  - Keyboard shortcuts via clientside event listeners
  - High-performance Cytoscape visualization with animated highlighting
  - Layout selector (Dagre, CoSE, Concentric, Circular, Breadthfirst)
  - Interactive search panel by address, name, or symbol
  - Graph Legend and node inspector details (including binary section, recursion, size)
  - Synchronized SMT & Symbolic Execution explanations
  - Printable HTML-to-PDF ready reports
"""
from __future__ import annotations

import base64, json, os, tempfile, time, threading, uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

import dash
import dash_cytoscape as cyto
import networkx as nx
import numpy as np
from dash import Input, Output, State, ctx, dcc, html, no_update, ALL, MATCH
from dash.exceptions import PreventUpdate
from dataclasses import asdict

from core.binary_loader import BinaryLoader
from graph.graph_builder import GraphBuilder
from core.interfaces import AnalysisBackendProvider

try:
    cyto.load_extra_layouts()
except Exception:
    pass

# ── Theme styles ──────────────────────────────────────────────────────────────
# CSS styles injection for Light/Dark toggling, Keyboard shortcuts, Legend, and Print
THEME_CSS = """
:root {
    --bg: #0d1117;
    --panel: #161b22;
    --card: #1c2128;
    --border: #21262d;
    --bhi: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --dim: #484f58;
    --blue: #58a6ff;
    --green: #3fb950;
    --red: #f85149;
    --yellow: #e3b341;
    --purple: #8957e5;
    --cyan: #39d353;
    --orange: #db6d28;
    --pink: #f78166;
}

.theme-light {
    --bg: #f6f8fa;
    --panel: #ffffff;
    --card: #eaeef2;
    --border: #d0d7de;
    --bhi: #d8dee4;
    --text: #24292f;
    --muted: #57606a;
    --dim: #8c959f;
    --blue: #0969da;
    --green: #1a7f37;
    --red: #cf222e;
    --yellow: #9a6700;
    --purple: #8250df;
    --cyan: #11a277;
    --orange: #bc4c00;
    --pink: #d1573f;
}

body {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    transition: background-color 0.2s, color 0.2s;
    margin: 0;
    font-family: 'Inter', sans-serif;
}

/* Legend Styling */
.legend-overlay {
    position: absolute;
    bottom: 60px;
    left: 15px;
    background-color: var(--panel);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 10px;
    z-index: 100;
    font-size: 11px;
    width: 170px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
}

.legend-item {
    display: flex;
    align-items: center;
    margin-bottom: 5px;
}

.legend-color {
    width: 12px;
    height: 12px;
    border-radius: 2px;
    margin-right: 8px;
    border: 1px solid var(--border);
}

/* Tooltip overlay styling */
.tooltip-stat {
    position: relative;
    display: inline-block;
    cursor: help;
}

.tooltip-stat .tooltip-text {
    visibility: hidden;
    width: 180px;
    background-color: var(--panel);
    color: var(--text);
    border: 1px solid var(--border);
    text-align: center;
    border-radius: 6px;
    padding: 6px 8px;
    position: absolute;
    z-index: 9999;
    bottom: 125%;
    left: 50%;
    margin-left: -90px;
    opacity: 0;
    transition: opacity 0.2s;
    font-size: 11px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.25);
}

.tooltip-stat:hover .tooltip-text {
    visibility: visible;
    opacity: 1;
}

/* Fullscreen mode classes */
.fullscreen-active {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 1000 !important;
    background-color: var(--bg) !important;
}

/* Dropdown styling overrides */
.Select-control {
    background-color: var(--card) !important;
    border-color: var(--border) !important;
    color: var(--text) !important;
}
.Select-menu-outer {
    background-color: var(--card) !important;
    border-color: var(--border) !important;
    z-index: 1000 !important;
}
.Select-option {
    background-color: var(--card) !important;
    color: var(--text) !important;
}
.Select-option.is-focused {
    background-color: var(--bhi) !important;
}
.Select-value-label {
    color: var(--text) !important;
}
.VirtualizedSelectFocusedOption {
    background-color: var(--bhi) !important;
    color: var(--text) !important;
}

/* Scrollbar tweaks */
::-webkit-scrollbar {
    width: 6px;
    height: 6px;
}
::-webkit-scrollbar-track {
    background: var(--bg);
}
::-webkit-scrollbar-thumb {
    background: var(--bhi);
    border-radius: 3px;
}

/* Table styling */
table.sym-table-styled {
    width: 100%;
    border-collapse: collapse;
    margin-top: 10px;
    font-size: 11px;
    color: var(--text);
}
table.sym-table-styled th {
    border-bottom: 1px solid var(--border);
    padding: 6px;
    text-align: left;
    color: var(--muted);
    font-weight: 600;
}
table.sym-table-styled td {
    padding: 6px;
    border-bottom: 1px solid var(--border);
}

/* Print CSS variables & formatting */
@media print {
    body {
        background: white !important;
        color: black !important;
    }
    .no-print {
        display: none !important;
    }
}
"""

# (icon, label, bg, fg) for each event type
EVENT_META: Dict[str, tuple] = {
    "ENTRY":        ("▶",  "ENTRY",    "#1a4731", "#3fb950"),
    "RETURN":       ("↩",  "RETURN",   "#2d1a05", "#db6d28"),
    "BRANCH":       ("⑂",  "BRANCH",   "#2d2409", "#e3b341"),
    "LOOP":         ("↻",  "LOOP",     "#063535", "#39d353"),
    "LIBRARY_CALL": ("📚", "LIB CALL", "#1a0f3d", "#8957e5"),
    "SYSCALL":      ("⚙",  "SYSCALL",  "#2d2009", "#d29922"),
    "NORMAL":       ("→",  "NORMAL",   "#21262d", "#8b949e"),
}

LAYOUTS = [
    {"label": "⬡ Hierarchical (Dagre)",  "value": "dagre"},
    {"label": "✦ Force-Directed (CoSE)",   "value": "cose"},
    {"label": "◎ Concentric Circle",       "value": "concentric"},
    {"label": "◉ Circular Ring",           "value": "circle"},
    {"label": "⟶ Breadth-First Tree",     "value": "breadthfirst"},
]

# ── Style helpers ─────────────────────────────────────────────────────────────

def _merge(*dicts: dict) -> dict:
    out: dict = {}
    for d in dicts:
        out.update(d)
    return out


def _section(text: str, color_var: str = "--blue") -> html.Div:
    return html.Div(text, style={
        "fontSize": "10px", "fontWeight": "700", "letterSpacing": "0.10em",
        "textTransform": "uppercase", "color": f"var({color_var})",
        "marginBottom": "8px", "fontFamily": "Inter, sans-serif",
    })


def _badge(text: str, bg: str, fg: str, extra: Optional[dict] = None) -> html.Span:
    s = {
        "backgroundColor": bg, "color": fg, "borderRadius": "4px",
        "padding": "2px 9px", "fontSize": "11px", "fontWeight": "600",
        "fontFamily": "JetBrains Mono, monospace", "display": "inline-block",
    }
    if extra:
        s.update(extra)
    return html.Span(text, style=s)


def _event_badge(event_type: str) -> html.Span:
    icon, label, bg, fg = EVENT_META.get(event_type, EVENT_META["NORMAL"])
    return _badge(f"{icon} {label}", bg, fg, {"marginRight": "4px"})


def _kv(key: str, val: Any, val_color_var: str = "--text") -> html.Div:
    return html.Div([
        html.Span(key + ": ", style={"color": "var(--muted)", "fontSize": "12px"}),
        html.Span(str(val), style={
            "color": f"var({val_color_var})",
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "12px",
        }),
    ], style={"marginBottom": "4px"})


def _metric(label: str, value: Any, color_var: str = "--blue", tooltip_text: str = "") -> html.Div:
    card_content = html.Div([
        html.Div(str(value), style={
            "fontSize": "16px", "fontWeight": "700",
            "color": f"var({color_var})",
            "fontFamily": "JetBrains Mono, monospace", "lineHeight": "1.2",
        }),
        html.Div(label, style={
            "fontSize": "9px", "color": "var(--muted)",
            "textTransform": "uppercase", "letterSpacing": "0.06em",
        }),
    ], style={
        "backgroundColor": "var(--card)", "border": "1px solid var(--border)",
        "borderRadius": "6px", "padding": "8px 10px",
        "flex": "1", "minWidth": "78px",
    })
    
    if tooltip_text:
        return html.Div(className="tooltip-stat", children=[
            card_content,
            html.Span(className="tooltip-text", children=tooltip_text)
        ])
    return card_content


def _play_btn(color_var: str = "--muted") -> dict:
    return {
        "backgroundColor": "var(--card)",
        "color": f"var({color_var})",
        "border": "1px solid var(--border)",
        "borderRadius": "6px", "padding": "6px 0",
        "cursor": "pointer", "fontSize": "14px",
        "fontFamily": "monospace", "flex": "1",
        "transition": "background-color 0.15s, color 0.15s",
    }


def _btn(label: str, bg: str, fg: str, extra: Optional[dict] = None) -> dict:
    s = {
        "backgroundColor": bg, "color": fg,
        "border": f"1px solid {fg}", "borderRadius": "6px",
        "padding": "5px 14px", "cursor": "pointer",
        "fontFamily": "Inter, sans-serif", "fontSize": "12px",
        "fontWeight": "500",
    }
    if extra:
        s.update(extra)
    return s

# ── Graph helpers ─────────────────────────────────────────────────────────────

def nx_to_cyto(G: nx.DiGraph) -> List[dict]:
    """Convert NetworkX graph to Cytoscape element list."""
    elements: List[dict] = []
    for node, data in G.nodes(data=True):
        classes = data.get("node_class", "internal")
        if data.get("is_loop_header"):
            classes += " loop-header"
        if data.get("gnn_predicted_vulnerable"):
            classes += " gnn-vulnerable-node"
        d = {
            k: (json.dumps(list(v)) if isinstance(v, (list, set)) else v)
            for k, v in data.items()
        }
        elements.append({"data": {"id": str(node), **d}, "classes": classes})
    for src, dst in G.edges():
        elements.append({"data": {"source": str(src), "target": str(dst)}})
    return elements


def _next_vis(trace: List[dict], idx: int, direction: int, hide_lib: bool) -> int:
    n = len(trace)
    while True:
        idx += direction
        if idx < 0:
            return 0
        if idx >= n:
            return n - 1
        if not hide_lib or not trace[idx].get("is_library", False):
            return idx


def _build_layout(name: str) -> dict:
    base = {"name": name, "animate": True, "animationDuration": 250}
    extras: dict = {
        "dagre":        {"rankDir": "TB", "nodeSep": 50, "rankSep": 80, "padding": 30},
        "cose":         {"nodeRepulsion": 400000, "idealEdgeLength": 90, "gravity": 75,
                         "padding": 40, "randomize": False},
        "concentric":   {"minNodeSpacing": 60, "padding": 40},
        "circle":       {"padding": 40, "startAngle": 0},
    }
    return _merge(base, extras.get(name, {}))


def _cyto_stylesheet() -> List[dict]:
    return [
        {"selector": "node", "style": {
            "label": "data(label)",
            "text-valign": "center", "text-halign": "center",
            "color": "var(--text)",
            "font-family": "JetBrains Mono, monospace",
            "font-size": "10px", "text-wrap": "wrap", "text-max-width": "110px",
            "width": "label", "height": "label", "padding": "7px",
            "shape": "rectangle",
            "background-color": "var(--card)",
            "border-width": 1, "border-color": "var(--border)",
        }},
        {"selector": ".entry", "style": {
            "background-color": "var(--panel)", "border-color": "var(--green)",
            "border-width": 2, "shape": "diamond",
            "color": "var(--green)", "font-weight": "bold",
        }},
        {"selector": ".library", "style": {
            "background-color": "var(--panel)", "border-color": "var(--purple)",
            "shape": "round-rectangle", "color": "var(--purple)",
        }},
        {"selector": ".syscall", "style": {
            "background-color": "var(--panel)", "border-color": "var(--yellow)",
            "color": "var(--yellow)",
        }},
        {"selector": ".internal", "style": {
            "background-color": "var(--card)", "border-color": "var(--blue)", "color": "var(--blue)",
        }},
        {"selector": ".loop-header", "style": {
            "border-color": "var(--cyan)", "border-width": 2, "border-style": "dashed",
        }},
        {"selector": ".active-execution-node", "style": {
            "background-color": "var(--card)", "border-color": "var(--red)",
            "border-width": 3, "color": "var(--red)",
            "font-weight": "bold", "z-index": 999,
        }},
        {"selector": ".visited-execution-node", "style": {
            "background-color": "var(--panel)", "border-color": "var(--purple)", "color": "var(--pink)",
            "opacity": 0.8
        }},
        {"selector": ".branch-node", "style": {
            "border-style": "dashed", "border-color": "var(--yellow)", "border-width": 3,
        }},
        {"selector": "edge", "style": {
            "curve-style": "bezier", "target-arrow-shape": "triangle",
            "line-color": "var(--border)", "target-arrow-color": "var(--border)",
            "width": 1.5, "opacity": 0.6,
        }},
        {"selector": ".active-edge", "style": {
            "line-color": "var(--red)", "target-arrow-color": "var(--red)",
            "width": 3, "line-style": "dashed", "opacity": 1,
        }},
        {"selector": ".visited-edge", "style": {
            "line-color": "var(--purple)", "target-arrow-color": "var(--purple)",
            "width": 2, "opacity": 0.7,
        }},
        {"selector": "node:selected", "style": {
            "border-color": "var(--blue)", "border-width": 3,
        }},
        # Vulnerable / crashing node — glowing crimson
        {"selector": ".vulnerable-node", "style": {
            "background-color": "#2d0808",
            "border-color": "#f85149",
            "border-width": 3,
            "color": "#f85149",
            "font-weight": "bold",
            "z-index": 999,
            "shadow-blur": 16,
            "shadow-color": "#f85149",
            "shadow-opacity": 0.9,
            "shadow-offset-x": 0,
            "shadow-offset-y": 0,
        }},
        # GNN predicted vulnerable node — glowing orange
        {"selector": ".gnn-vulnerable-node", "style": {
            "background-color": "#2d1b09",
            "border-color": "#db6d28",
            "border-width": 2,
            "color": "#db6d28",
            "font-weight": "bold",
            "z-index": 998,
            "shadow-blur": 12,
            "shadow-color": "#db6d28",
            "shadow-opacity": 0.85,
            "shadow-offset-x": 0,
            "shadow-offset-y": 0,
        }},
    ]

# ── Report generator ──────────────────────────────────────────────────────────

def _make_report(filename: str, trace: List[dict], metrics: dict, ts: str) -> str:
    rows = ""
    for i, s in enumerate(trace):
        evt = s.get("event_type", "NORMAL")
        icon, label, bg, fg = EVENT_META.get(evt, EVENT_META["NORMAL"])
        smt = s.get("smt_diagnostics", {})
        sat = smt.get("status", "N/A")
        sc = "#3fb950" if sat == "SAT" else "#f85149" if sat == "UNSAT" else "#8b949e"
        rows += (
            f"<tr><td>{i}</td>"
            f"<td style='color:#58a6ff;font-family:monospace'>{s.get('instruction_address','')}</td>"
            f"<td>{s.get('function_name','')}</td>"
            f"<td><span style='background:{bg};color:{fg};padding:2px 8px;border-radius:3px;"
            f"font-size:11px'>{icon} {label}</span></td>"
            f"<td style='font-size:11px'>{str(s.get('explanation',''))[:110]}…</td>"
            f"<td style='color:{sc};font-family:monospace'>{sat}</td></tr>"
        )

    mc = "".join(
        f"<div class='mc'><div class='mv'>{v}</div>"
        f"<div class='ml'>{k.replace('_',' ').title()}</div></div>"
        for k, v in (metrics or {}).items() if k != "filename"
    )

    findings = [
        ("Total execution states",   len(trace)),
        ("Branch points",            sum(1 for s in trace if s.get("is_branch"))),
        ("Library calls",            sum(1 for s in trace if s.get("event_type") == "LIBRARY_CALL")),
        ("Loop back-edges",          sum(1 for s in trace if s.get("event_type") == "LOOP")),
        ("Return events",            sum(1 for s in trace if s.get("event_type") == "RETURN")),
        ("SAT paths",                sum(1 for s in trace if s.get("smt_diagnostics", {}).get("status") == "SAT")),
        ("UNSAT paths",              sum(1 for s in trace if s.get("smt_diagnostics", {}).get("status") == "UNSAT")),
        ("Unique functions visited", len(set(s.get("function_name", "") for s in trace))),
    ]
    fr = "".join(f"<tr><td>{k}</td><td><strong>{v}</strong></td></tr>" for k, v in findings)

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Analysis Report — {filename}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:24px}}
h1{{color:#58a6ff;font-size:22px;border-bottom:1px solid #21262d;padding-bottom:12px;margin-top:0}}
h2{{color:#8b949e;font-size:11px;text-transform:uppercase;letter-spacing:.08em;margin-top:28px}}
table{{width:100%;border-collapse:collapse;margin-top:8px;font-size:12px}}
th{{background:#161b22;color:#8b949e;padding:7px 10px;text-align:left;border:1px solid #21262d;font-weight:600}}
td{{padding:6px 10px;border:1px solid #21262d;vertical-align:top}}
tr:nth-child(even)td{{background:#0d1117}}tr:nth-child(odd)td{{background:#161b22}}
.mg{{display:flex;flex-wrap:wrap;gap:10px;margin-top:8px}}
.mc{{background:#161b22;border:1px solid #21262d;border-radius:6px;padding:10px 14px;min-width:130px}}
.mv{{font-size:20px;font-weight:700;color:#58a6ff;font-family:monospace}}
.ml{{font-size:10px;color:#8b949e;text-transform:uppercase;letter-spacing:.06em}}
.footer{{margin-top:40px;color:#484f58;font-size:11px;border-top:1px solid #21262d;padding-top:14px}}
@media print {{
    body {{ background: white !important; color: black !important; font-size: 11px; }}
    table {{ border: 1px solid #ddd; }}
    th, td {{ border: 1px solid #ddd; padding: 4px; }}
    tr {{ page-break-inside: avoid; }}
}}
</style></head><body>
<h1>🔬 Neuro-Symbolic Fuzzer — Analysis Report</h1>
<p style="color:#8b949e">Binary: <code style="color:#58a6ff">{filename}</code>
&nbsp;·&nbsp;Generated: {ts}</p>
<h2>Analysis Metrics</h2><div class="mg">{mc}</div>
<h2>Execution Trace ({len(trace)} states)</h2>
<table><thead><tr>
  <th>#</th><th>Address</th><th>Function</th><th>Event</th><th>Explanation</th><th>SMT</th>
</tr></thead><tbody>{rows}</tbody></table>
<h2>Findings</h2>
<table><thead><tr><th>Finding</th><th>Value</th></tr></thead><tbody>{fr}</tbody></table>
<div class="footer">
  Neuro-Symbolic Fuzzer &nbsp;·&nbsp; angr symbolic execution + Z3 SMT solver
  &nbsp;·&nbsp; {ts}
</div></body></html>"""


# ── Global analysis tracking state ───────────────────────────────────────────
ACTIVE_ANALYSES: Dict[str, Dict[str, Any]] = {}
ACTIVE_ANALYSES_LOCK = threading.Lock()


def run_analysis_worker(analysis_id: str, decoded_bytes: bytes, filename: str) -> None:
    # Configurable hard timeout (default 5 min) to prevent infinite path explosion hangs.
    _TIMEOUT_S = int(os.environ.get("NSF_ANALYSIS_TIMEOUT_S", "300"))
    _deadline = time.perf_counter() + _TIMEOUT_S

    def _timed_out() -> bool:
        return time.perf_counter() > _deadline

    tmp = None
    try:
        # Create temp file
        fd, tmp = tempfile.mkstemp(prefix="angr_target_")
        with open(tmp, "wb") as f:
            f.write(decoded_bytes)
        os.close(fd)

        if _timed_out():
            raise TimeoutError(f"Analysis timed out after {_TIMEOUT_S}s during loader init.")

        # 1. Loader & initial analyze
        loader = BinaryLoader(tmp)
        loader.analyze()

        # 2. CFG & CG Builder
        builder = GraphBuilder(loader)
        nx_cfg = builder.build_networkx_cfg()
        nx_cg  = builder.build_networkx_cg()

        # Initialize shared_logs early so GNN inference can log to it
        with ACTIVE_ANALYSES_LOCK:
            ACTIVE_ANALYSES[analysis_id]["logs"] = ACTIVE_ANALYSES[analysis_id].get("logs", [])
            shared_logs = ACTIVE_ANALYSES[analysis_id]["logs"]

        # Run GNN pre-filter inference if model exists
        gnn_vuln_count = 0
        func_vuln_map = None
        try:
            app_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(app_dir, "..", ".."))
            model_path = os.path.join(project_root, "model.pt")
            temp_path = os.path.join(project_root, "model_temperature.json")
            if os.path.exists(model_path):
                import torch
                import torch.nn.functional as F
                from ml.gnn_model import VulnGNN, create_model

                nodes = list(nx_cfg.nodes())
                node_to_idx = {node_addr: idx for idx, node_addr in enumerate(nodes)}
                
                # Use 40 features (updated feature extractor)
                x_list = [nx_cfg.nodes[n].get('features', [0.0] * 40) for n in nodes]

                edge_sources = []
                edge_targets = []
                for src, dst in nx_cfg.edges():
                    if src in node_to_idx and dst in node_to_idx:
                        edge_sources.append(node_to_idx[src])
                        edge_targets.append(node_to_idx[dst])

                x = torch.tensor(x_list, dtype=torch.float)
                if edge_sources:
                    edge_index = torch.tensor([edge_sources, edge_targets], dtype=torch.long)
                else:
                    edge_index = torch.empty((2, 0), dtype=torch.long)

                # Load model with new architecture (40 input features, 128 hidden)
                checkpoint = torch.load(model_path, map_location='cpu')
                config = checkpoint.get('config', {
                    'input_dim': 40,
                    'hidden_dim': 128,
                    'num_layers': 3,
                    'encoder': 'sage',
                    'dropout': 0.3
                })
                model = create_model(**config)
                model.load_state_dict(checkpoint['model_state_dict'])
                model.eval()

                # Load temperature for calibration
                temperature = 1.0
                if os.path.exists(temp_path):
                    with open(temp_path) as f:
                        temp_data = json.load(f)
                    temperature = temp_data.get('temperature', 1.0)
                    model.set_temperature(temperature)

                with torch.no_grad():
                    # Use calibrated probabilities with temperature scaling
                    probs = model.predict_proba(x, edge_index)
                    vuln_probs = probs[:, 1].numpy()  # Probability of class 1 (vulnerable)

                # Per-binary calibration: adapt threshold based on binary's statistics
                # Use validation-derived optimal threshold if available, else fallback
                threshold_path = os.path.join(project_root, "model_threshold.json")
                if os.path.exists(threshold_path):
                    with open(threshold_path) as f:
                        thresh_data = json.load(f)
                    VULN_THRESHOLD = thresh_data.get('threshold', 0.5)
                else:
                    # Adaptive threshold: use percentile-based approach
                    # Target: flag top ~5% of blocks as candidates, minimum 0.3
                    if len(vuln_probs) > 20:
                        percentile_95 = np.percentile(vuln_probs, 95)
                        VULN_THRESHOLD = max(0.3, min(0.8, percentile_95))
                    else:
                        VULN_THRESHOLD = 0.5  # Default for small graphs

                # Per-basic-block predictions with calibrated threshold
                bb_vuln_flags = vuln_probs > VULN_THRESHOLD

                # Aggregate to function level using the call graph
                # A function is vulnerable if ANY of its basic blocks exceeds threshold
                func_vuln_map = {}  # func_addr -> bool
                for idx, node_addr in enumerate(nodes):
                    if bb_vuln_flags[idx]:
                        # Find which function this basic block belongs to
                        func_addr = None
                        for func_node_addr in nx_cg.nodes():
                            func_data = nx_cg.nodes[func_node_addr]
                            func_blocks = func_data.get('block_addrs', set())
                            if node_addr in func_blocks:
                                func_addr = func_node_addr
                                break

                        if func_addr is not None:
                            func_vuln_map[func_addr] = True
                            # Also mark the basic block for visualization
                            nx_cfg.nodes[node_addr]["gnn_predicted_vulnerable"] = True
                            gnn_vuln_count += 1

                # Log function-level results
                vuln_func_count = len(func_vuln_map)
                shared_logs.append({
                    "ts": time.time(),
                    "level": "SUCCESS",
                    "msg": f"GNN Pre-Filter: {vuln_func_count} function(s) flagged as potentially vulnerable "
                           f"(from {gnn_vuln_count} basic blocks with P(vuln) > {VULN_THRESHOLD:.2f}, temp={temperature:.2f})."
                })
        except Exception as e:
            import sys
            print(f"[GNN-UI-ERROR] Failed GNN inference overlay: {e}", file=sys.stderr)

        cfg_elements = nx_to_cyto(nx_cfg)
        cg_elements  = nx_to_cyto(nx_cg)

        # 3. Symbolic execution backend
        backend = AnalysisBackendProvider(tmp, original_filename=filename, gnn_vulnerable_functions=func_vuln_map)

        # Sync backend to active analyses, and map its solver_events to our shared log
        with ACTIVE_ANALYSES_LOCK:
            ACTIVE_ANALYSES[analysis_id]["backend"] = backend
            # shared_logs already initialized above
            shared_logs = ACTIVE_ANALYSES[analysis_id]["logs"]

            # Log GNN pre-filter results to UI console (already done above if model exists)
            app_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(app_dir, "..", ".."))
            if not os.path.exists(os.path.join(project_root, "model.pt")):
                shared_logs.append({
                    "ts": time.time(),
                    "level": "WARN",
                    "msg": "GNN Pre-Filter: model.pt not found. Run trainer.py to enable prediction overlay."
                })

            shared_logs.extend(backend.solver_events)
            backend.solver_events = shared_logs

        t0 = time.perf_counter()
        raw_trace = backend.get_execution_trace()

        trace: List[dict] = []
        sat_n = unsat_n = total_constraints = total_solver_time = 0
        for state_obj in raw_trace:
            d: Dict[str, Any] = asdict(state_obj)
            smt_obj = backend.get_constraint_result(state_obj)
            sd = asdict(smt_obj)
            d["smt_diagnostics"] = sd
            s = sd.get("status", "N/A")
            if s == "SAT":   sat_n += 1
            elif s == "UNSAT": unsat_n += 1
            total_constraints += len(sd.get("constraint_annotations", []))
            total_solver_time += sd.get("solver_time_ms", 0.0)
            trace.append(d)

        # 4. Vulnerability scan (emits events in real-time to solver_events)
        vulns = backend.scan_vulnerabilities()

        # Cleanup temp file handled in finally block

        lib_funcs = sum(1 for _, d in nx_cg.nodes(data=True) if d.get("is_library_call"))
        elapsed   = round(time.perf_counter() - t0, 2)

        # Calculate metrics
        discovered_branches = [node for node in nx_cfg.nodes() if nx_cfg.out_degree(node) > 1]
        visited_nodes = {int(s.get("instruction_address", "0"), 16) for s in trace if s.get("instruction_address")}
        total_branch_edges = sum(nx_cfg.out_degree(node) for node in discovered_branches)
        visited_branch_edges = 0
        
        visited_edges = set()
        for i in range(len(trace) - 1):
            src_str = trace[i].get("instruction_address", "")
            dst_str = trace[i+1].get("instruction_address", "")
            if src_str and dst_str:
                try:
                    src = int(src_str, 16)
                    dst = int(dst_str, 16)
                    if nx_cfg.has_edge(src, dst):
                        visited_edges.add((src, dst))
                except ValueError:
                    pass
        
        for node in discovered_branches:
            if node in visited_nodes:
                for succ in nx_cfg.successors(node):
                    if (node, succ) in visited_edges:
                        visited_branch_edges += 1
        
        branch_cov_val = (visited_branch_edges / max(total_branch_edges, 1)) * 100
        branch_cov = f"{branch_cov_val:.1f}%"
        
        active_paths = len(backend.engine.simgr.active)
        deadended_paths = len(backend.engine.simgr.deadended)
        unsat_paths = len(backend.engine.simgr.unsat)
        errored_paths = len(backend.engine.simgr.errored)
        explored_paths = active_paths + deadended_paths + unsat_paths + errored_paths
        
        max_depth = max((s.get("execution_depth", 0) for s in trace), default=0)
        max_solver = max((s.get("smt_diagnostics", {}).get("solver_time_ms", 0.0) for s in trace), default=0.0)
        
        all_sym_vars = set()
        for s in trace:
            sym_list = s.get("smt_diagnostics", {}).get("symbolic_variables_list", [])
            for v in sym_list:
                all_sym_vars.add(v.get("name"))
        total_sym_vars = len(all_sym_vars)
        
        avg_c = round(total_constraints / max(len(trace), 1), 1)

        cc_list = [d.get("cyclomatic_complexity", 1) for _, d in nx_cg.nodes(data=True) if d.get("cyclomatic_complexity") is not None]
        avg_cc = round(sum(cc_list) / max(len(cc_list), 1), 1)

        metrics = {
            "total_functions":    nx_cg.number_of_nodes(),
            "library_functions":  lib_funcs,
            "user_functions":     nx_cg.number_of_nodes() - lib_funcs,
            "total_basic_blocks": nx_cfg.number_of_nodes(),
            "cfg_edges":          nx_cfg.number_of_edges(),
            "execution_states":   len(trace),
            "sat_paths":          sat_n,
            "unsat_paths":        unsat_paths,
            "branch_coverage":    branch_cov,
            "avg_constraints":    avg_c,
            "analysis_time_s":    elapsed,
            "filename":           filename,
            "avg_cyclomatic":     avg_cc,
            "avg_solver_time":    round(total_solver_time / max(len(trace), 1), 2),
            "total_solver_calls": len(trace),
            "max_depth":          max_depth,
            "explored_paths":     explored_paths,
            "active_paths":       active_paths,
            "deadended_paths":    deadended_paths,
            "max_solver_time":    round(max_solver, 2),
            "total_sym_vars":     total_sym_vars,
        }
        mitigations = loader.get_mitigations()
        binary_info = {
            "filename":   filename,
            "size_bytes": len(decoded_bytes),
            "timestamp":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "mitigations": mitigations,
        }

        with ACTIVE_ANALYSES_LOCK:
            ACTIVE_ANALYSES[analysis_id].update({
                "status": "done",
                "result": {
                    "status_msg": f"✅  {filename}  —  analyzed in {elapsed}s",
                    "cfg_elements": cfg_elements,
                    "cg_elements": cg_elements,
                    "trace": trace,
                    "metrics": metrics,
                    "binary_info": binary_info,
                    "vulns": vulns,
                }
            })
    except Exception as e:
        import traceback
        err_msg = f"Analysis error: {str(e)}\n{traceback.format_exc()}"
        with ACTIVE_ANALYSES_LOCK:
            ACTIVE_ANALYSES[analysis_id].update({
                "status": "error",
                "error_msg": err_msg
            })
    finally:
        if tmp and os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> dash.Dash:
    app = dash.Dash(
        __name__,
        external_stylesheets=[
            "https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600"
            "&family=Inter:wght@300;400;500;600;700&display=swap",
        ],
        suppress_callback_exceptions=True,
    )
    app.title = "Neuro-Symbolic Fuzzer"

    # Define Stylesheet & Keyboard shortcut client listener
    app.index_string = f"""
    <!DOCTYPE html>
    <html>
        <head>
            {{%metas%}}
            <title>{{%title%}}</title>
            {{%favicon%}}
            {{%css%}}
            <style>{THEME_CSS}</style>
        </head>
        <body class="theme-dark">
            {{%app_entry%}}
            <footer>
                {{%config%}}
                {{%scripts%}}
                {{%renderer%}}
            </footer>
        </body>
    </html>
    """

    # ── Shared panel style snippets ───────────────────────────────────────────
    _left_style = {
        "width": "300px", "flexShrink": "0",
        "backgroundColor": "var(--panel)",
        "borderRight": "1px solid var(--border)",
        "padding": "16px", "overflowY": "auto",
        "fontFamily": "Inter, sans-serif",
    }
    _right_style = {
        "width": "390px", "flexShrink": "0",
        "backgroundColor": "var(--panel)",
        "borderLeft": "1px solid var(--border)",
        "padding": "16px", "overflowY": "auto",
        "fontFamily": "Inter, sans-serif",
    }
    _card_s = {
        "backgroundColor": "var(--card)",
        "border": "1px solid var(--border)",
        "borderRadius": "6px", "padding": "12px",
        "marginBottom": "12px",
    }
    _hr = html.Hr(style={"borderColor": "var(--border)", "margin": "14px 0"})

    # ── Layout definition ─────────────────────────────────────────────────────

    header = html.Div([
        # Logo
        html.Div([
            html.Span("🔬", style={"fontSize": "18px", "marginRight": "8px"}),
            html.Span("NEURO-SYMBOLIC FUZZER", style={
                "fontFamily": "JetBrains Mono, monospace", "fontWeight": "700",
                "fontSize": "13px", "letterSpacing": "0.12em", "color": "var(--blue)",
            }),
            html.Span("  //  re-tool", style={
                "fontFamily": "JetBrains Mono, monospace", "fontWeight": "400",
                "fontSize": "11px", "color": "var(--dim)",
            }),
        ], style={"display": "flex", "alignItems": "center"}),

        # Binary badge
        html.Div(id="header-binary-info", children="No binary loaded", style={
            "fontFamily": "JetBrains Mono, monospace", "fontSize": "12px", "color": "var(--muted)",
        }),

        # Controls
        html.Div([
            html.Button("☀️/🌙 Toggle Theme", id="btn-theme", n_clicks=0,
                        style=_btn("Theme", "transparent", "var(--text)", {"marginRight": "10px"})),
            html.Button("📄 Export Report", id="btn-export", n_clicks=0,
                        style=_btn("export", "#1a2d1a", "var(--green)", {"marginRight": "10px"})),
            html.Button("🛡️ Export SARIF", id="btn-export-sarif", n_clicks=0,
                        style=_btn("export-sarif", "#1a243d", "var(--blue)", {"marginRight": "10px"})),
            dcc.Download(id="download-report"),
            dcc.Download(id="download-sarif"),
        ], style={"display": "flex", "alignItems": "center"}),

    ], style={
        "display": "flex", "alignItems": "center",
        "justifyContent": "space-between",
        "backgroundColor": "var(--panel)",
        "borderBottom": "1px solid var(--border)",
        "padding": "0 20px", "height": "50px", "flexShrink": "0",
    })

    # ── Left panel ────────────────────────────────────────────────────────────
    left_panel = html.Div([

        _section("01  ·  Binary Upload", "--blue"),
        dcc.Upload(id="upload-binary", multiple=False,
                   children=html.Div([
                       html.Div("⬆", style={"fontSize": "22px", "marginBottom": "3px"}),
                       html.Div("Drag & Drop or Click to Upload",
                                style={"fontSize": "12px", "fontWeight": "500"}),
                       html.Div("ELF · Mach-O · PE",
                                style={"fontSize": "10px", "color": "var(--dim)", "marginTop": "2px"}),
                   ], style={"textAlign": "center"}),
                   style={
                       "border": "2px dashed var(--bhi)", "borderRadius": "8px",
                       "padding": "14px", "cursor": "pointer",
                       "backgroundColor": "var(--card)", "marginBottom": "8px",
                   }),
        dcc.Loading(type="dot", color="var(--blue)",
                    children=html.Div(id="upload-status", style={
                        "fontSize": "12px", "marginBottom": "14px", "color": "var(--green)",
                    })),

        _hr,
        _section("02  ·  Graph View & Search", "--blue"),
        dcc.Dropdown(id="graph-selector", clearable=False,
                     options=[
                         {"label": "⬡  Control Flow Graph (CFG)", "value": "cfg"},
                         {"label": "☎  Call Graph (CG)",          "value": "cg"},
                     ],
                     value="cfg", style={"marginBottom": "8px", "fontSize": "12px"}),
        dcc.Dropdown(id="layout-selector", clearable=False,
                     options=LAYOUTS, value="dagre",
                     style={"marginBottom": "8px", "fontSize": "12px"}),
        
        # Search panel
        dcc.Input(id="search-input", placeholder="Search function, address, section...",
                  type="text", style={
                      "width": "100%", "backgroundColor": "var(--card)",
                      "border": "1px solid var(--border)", "borderRadius": "6px",
                      "padding": "6px 8px", "color": "var(--text)", "fontSize": "12px",
                      "marginBottom": "6px", "boxSizing": "border-box"
                  }),
        html.Div(id="search-results", style={"fontSize": "11px", "color": "var(--muted)"}),

        _hr,
        _section("03  ·  Analysis Metrics", "--blue"),
        html.Div(id="dashboard-metrics", children=[
            html.Div("Upload a binary to begin.",
                     style={"color": "var(--muted)", "fontSize": "12px"}),
        ], style={"marginBottom": "14px"}),

        _hr,
        _section("04  ·  Node Inspector", "--blue"),
        html.Div(id="node-inspector",
                 children=html.Div("Hover over a node to inspect.",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"marginBottom": "12px"})),

        _hr,
        _section("05  ·  Patch Verifier", "--purple"),
        dcc.Upload(id="upload-patch-original", children=html.Div("Upload Unpatched Binary", style={"fontSize": "11.5px"}),
                   style={"border": "1px dashed var(--bhi)", "borderRadius": "4px", "padding": "10px", "textAlign": "center", "marginBottom": "6px", "cursor": "pointer", "backgroundColor": "var(--card)"}),
        html.Div(id="upload-patch-original-status", style={"fontSize": "11px", "color": "var(--green)", "marginBottom": "6px"}),
        dcc.Upload(id="upload-patch-patched", children=html.Div("Upload Patched Binary", style={"fontSize": "11.5px"}),
                   style={"border": "1px dashed var(--bhi)", "borderRadius": "4px", "padding": "10px", "textAlign": "center", "marginBottom": "8px", "cursor": "pointer", "backgroundColor": "var(--card)"}),
        html.Div(id="upload-patch-patched-status", style={"fontSize": "11px", "color": "var(--green)", "marginBottom": "8px"}),
        html.Button("🔍 Verify Patch", id="btn-verify-patch", n_clicks=0, style={
            "width": "100%", "backgroundColor": "var(--purple)", "color": "white",
            "border": "none", "borderRadius": "4px", "padding": "8px", "cursor": "pointer",
            "fontSize": "11px", "fontWeight": "bold", "marginBottom": "8px"
        }),
        dcc.Loading(type="dot", color="var(--purple)", children=html.Div(id="patch-verify-status", style={"fontSize": "11px", "color": "var(--muted)"})),
        html.Div(id="patch-verifier-summary", style={"marginTop": "10px"}),

    ], style=_left_style)

    # ── Center panel (graph) ──────────────────────────────────────────────────
    # ── Center panel (graph + console) ────────────────────────────────────────
    center_panel = html.Div(id="center-graph-panel", children=[
        # Graph area
        html.Div([
            # Active-node floating badge
            html.Div(id="active-node-badge", style={
                "position": "absolute", "top": "10px", "left": "10px",
                "zIndex": "100", "pointerEvents": "none",
                "display": "flex", "gap": "6px", "alignItems": "center",
            }),

            # Cytoscape graph
            cyto.Cytoscape(
                id="cytoscape-graph",
                layout=_build_layout("dagre"),
                style={"width": "100%", "height": "100%"},
                elements=[],
                stylesheet=_cyto_stylesheet(),
                minZoom=0.04, maxZoom=4.0,
                boxSelectionEnabled=True,
                autoRefreshLayout=False,
            ),

            # Floating Graph Legend
            html.Div(className="legend-overlay", children=[
                html.Div("Legend", style={"fontWeight": "bold", "marginBottom": "6px", "borderBottom": "1px solid var(--border)", "paddingBottom": "3px"}),
                html.Div([html.Div(className="legend-color", style={"backgroundColor": "#3fb950"}), "Entry Block (Diamond)"], className="legend-item"),
                html.Div([html.Div(className="legend-color", style={"backgroundColor": "#58a6ff"}), "Internal Block (Rect)"], className="legend-item"),
                html.Div([html.Div(className="legend-color", style={"backgroundColor": "#8957e5"}), "Library Call (Round-rect)"], className="legend-item"),
                html.Div([html.Div(className="legend-color", style={"backgroundColor": "#e3b341"}), "Syscall Block"], className="legend-item"),
                html.Div([html.Div(className="legend-color", style={"borderColor": "#39d353", "borderStyle": "dashed", "borderWidth": "2px", "backgroundColor": "transparent"}), "Loop Header"], className="legend-item"),
                html.Div([html.Div(className="legend-color", style={"backgroundColor": "#f85149"}), "Active Execution State"], className="legend-item"),
                html.Div([html.Div(className="legend-color", style={"backgroundColor": "#7c3aed"}), "Visited Node / Path"], className="legend-item"),
            ]),

            # Floating Zoom & Fullscreen controls
            html.Div([
                html.Button("＋", id="btn-zoom-in",  title="Zoom In",
                            style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                                   "border": "1px solid var(--border)", "borderRadius": "6px",
                                   "width": "34px", "height": "34px", "cursor": "pointer",
                                   "fontSize": "18px", "lineHeight": "34px", "textAlign": "center",
                                   "padding": "0"}),
                html.Button("−", id="btn-zoom-out", title="Zoom Out",
                            style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                                   "border": "1px solid var(--border)", "borderRadius": "6px",
                                   "width": "34px", "height": "34px", "cursor": "pointer",
                                   "fontSize": "20px", "lineHeight": "34px", "textAlign": "center",
                                   "padding": "0"}),
                html.Button("⛶ Fit", id="btn-fit", title="Fit Graph",
                            style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                                   "border": "1px solid var(--border)", "borderRadius": "6px",
                                   "width": "54px", "height": "34px", "cursor": "pointer",
                                   "fontSize": "11px", "lineHeight": "34px", "textAlign": "center",
                                   "padding": "0", "marginTop": "4px"}),
                html.Button("⛶ Full", id="btn-fullscreen", title="Toggle Fullscreen",
                            style={"backgroundColor": "var(--panel)", "color": "var(--muted)",
                                   "border": "1px solid var(--border)", "borderRadius": "6px",
                                   "width": "54px", "height": "34px", "cursor": "pointer",
                                   "fontSize": "11px", "lineHeight": "34px", "textAlign": "center",
                                   "padding": "0", "marginTop": "4px"}),
            ], style={
                "position": "absolute", "bottom": "16px", "right": "16px",
                "display": "flex", "flexDirection": "column", "gap": "4px", "zIndex": "100",
            }),
        ], style={"flex": "1", "position": "relative", "minHeight": "0"}),

        # Live Solver Console panel
        html.Div([
            html.Div([
                html.Span("📟  LIVE SOLVER CONSOLE", style={
                    "fontFamily": "JetBrains Mono, monospace", "fontWeight": "700",
                    "fontSize": "11px", "letterSpacing": "0.1em", "color": "var(--blue)"
                }),
                html.Span(id="console-status", children="Idle", style={
                    "fontFamily": "JetBrains Mono, monospace", "fontSize": "10px", "color": "var(--muted)"
                })
            ], style={
                "display": "flex", "justifyContent": "space-between", "alignItems": "center",
                "paddingBottom": "6px", "borderBottom": "1px solid var(--border)"
            }),
            html.Div(
                id="console-logs-body",
                children="Console idle. Upload a binary to begin symbolic analysis.",
                style={
                    "flex": "1", "overflowY": "auto", "fontFamily": "JetBrains Mono, monospace",
                    "fontSize": "11px", "lineHeight": "1.6", "paddingTop": "6px", "whiteSpace": "pre-wrap",
                    "color": "var(--text)"
                }
            )
        ], style={
            "height": "220px", "borderTop": "1px solid var(--border)",
            "backgroundColor": "var(--panel)", "display": "flex", "flexDirection": "column",
            "padding": "8px 12px", "minHeight": "0"
        })
    ], style={"flex": "1", "display": "flex", "flexDirection": "column", "position": "relative", "backgroundColor": "var(--bg)", "minHeight": "0"})

    # ── Right panel (trace + SMT) ─────────────────────────────────────────────
    right_panel = html.Div([

        _section("Execution Trace", "--green"),

        # Playback controls
        html.Div([
            html.Button("⏮ First", id="btn-first", n_clicks=0, title="First State", style=_play_btn()),
            html.Button("◀",  id="btn-prev",  n_clicks=0, title="Previous",  style=_play_btn()),
            html.Button("▶",  id="btn-next",  n_clicks=0, title="Next",      style=_play_btn()),
            html.Button("⏭ Last",  id="btn-last",  n_clicks=0, title="Last State", style=_play_btn()),
            html.Button("⏯ Play",  id="btn-play",  n_clicks=0, title="Play/Pause",style=_play_btn("--green")),
        ], style={"display": "flex", "gap": "4px", "marginBottom": "8px"}),

        # Hide-library toggle
        dcc.Checklist(id="hide-library-toggle",
                      options=[{"label": "  Hide library calls", "value": "hide"}],
                      value=["hide"],
                      style={"fontSize": "11px", "color": "var(--muted)", "marginBottom": "8px"},
                      inputStyle={"marginRight": "5px"}),

        # Progress bar
        html.Div(id="trace-progress-label",
                 style={"fontSize": "11px", "color": "var(--muted)", "marginBottom": "4px"}),
        html.Div([
            html.Div(id="trace-progress-bar", style={
                "height": "3px", "backgroundColor": "var(--blue)",
                "borderRadius": "2px", "width": "0%",
                "transition": "width 0.3s ease",
            }),
        ], style={"backgroundColor": "var(--card)", "borderRadius": "2px", "marginBottom": "12px"}),

        # State viewer
        html.Div(id="state-viewer",
                 children=html.Div("Upload a binary and step through the trace.",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"minHeight": "140px"})),

        _hr,

        # SMT header
        html.Div([
            _section("SMT Constraint Diagnostics", "--purple"),
            html.Button("⚙ Advanced", id="btn-toggle-advanced", n_clicks=0, style={
                "backgroundColor": "transparent", "color": "var(--muted)",
                "border": "1px solid var(--border)", "borderRadius": "4px",
                "padding": "3px 10px", "cursor": "pointer",
                "fontSize": "11px", "fontFamily": "Inter, sans-serif",
            }),
        ], style={"display": "flex", "justifyContent": "space-between",
                  "alignItems": "center", "marginBottom": "10px"}),

        html.Div(id="smt-viewer",
                 children=html.Div("Waiting for SMT solver analysis details...",
                                   style={"color": "var(--muted)", "fontSize": "12px"}),
                 style=_merge(_card_s, {"borderLeft": "3px solid var(--purple)",
                                        "marginBottom": "0"})),

        html.Hr(style={"borderColor": "var(--border)", "margin": "14px 0"}),

        # ── Vulnerability & Exploit Center ────────────────────────────────
        html.Div([
            html.Span("🔴", style={"marginRight": "6px"}),
            html.Span("VULNERABILITY & EXPLOIT CENTER", style={
                "fontFamily": "JetBrains Mono, monospace", "fontWeight": "700",
                "fontSize": "11px", "letterSpacing": "0.1em", "color": "var(--red)",
            }),
        ], style={"marginBottom": "10px", "display": "flex", "alignItems": "center"}),

        html.Div(id="vuln-viewer",
                 children=html.Div("Upload a binary to scan for vulnerabilities.",
                                   style={"color": "var(--muted)", "fontSize": "12px",
                                          "fontStyle": "italic"}),
                 style=_merge(_card_s, {"borderLeft": "3px solid var(--red)",
                                        "marginBottom": "0"})),

        # Stores + interval
        dcc.Interval(id="play-interval", interval=900, n_intervals=0, disabled=True),
        dcc.Store(id="cfg-store"),
        dcc.Store(id="cg-store"),
        dcc.Store(id="trace-store",      data=[]),
        dcc.Store(id="trace-index",      data=0),
        dcc.Store(id="play-state",       data=False),
        dcc.Store(id="advanced-visible",   data=False),
        dcc.Store(id="metrics-store",    data={}),
        dcc.Store(id="binary-info-store", data={}),
        dcc.Store(id="theme-store",      data="dark"),
        dcc.Store(id="shortcut-dummy",   data=""),
        dcc.Store(id="vuln-store",       data=[]),
        dcc.Store(id="patch-original-path-store", data=None),
        dcc.Store(id="patch-patched-path-store",  data=None),
        dcc.Store(id="patch-verify-store",        data={}),

        # Live solver console stores & interval
        dcc.Store(id="analysis-id-store",  data=None),
        dcc.Interval(id="console-interval", interval=500, disabled=True),
        dcc.Store(id="console-log-store",  data=[]),

    ], style=_right_style)


    app.layout = html.Div([
        header,
        html.Div([left_panel, center_panel, right_panel],
                 style={"display": "flex", "flex": "1", "overflow": "hidden",
                        "minHeight": "0"}),
    ], id="main-container", style={
        "display": "flex", "flexDirection": "column",
        "height": "100vh", "overflow": "hidden",
        "backgroundColor": "var(--bg)",
        "fontFamily": "Inter, sans-serif",
    })

    # ── Callbacks ─────────────────────────────────────────────────────────────

    # Clientside keyboard shortcut handler (safe undefined guard)
    app.clientside_callback(
        """
        function(n_int) {
            if (!window.shortcut_listener_added) {
                window.shortcut_listener_added = true;
                document.addEventListener('keydown', function(e) {
                    if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) {
                        return;
                    }
                    var key = e.key || '';
                    if (key === 'ArrowRight') {
                        var btn = document.getElementById('btn-next');
                        if (btn) btn.click();
                    } else if (key === 'ArrowLeft') {
                        var btn = document.getElementById('btn-prev');
                        if (btn) btn.click();
                    } else if (key === ' ' || key === 'Spacebar') {
                        e.preventDefault();
                        var btn = document.getElementById('btn-play');
                        if (btn) btn.click();
                    } else if (key.toLowerCase() === 'r') {
                        var btn = document.getElementById('btn-reset');
                        if (btn) btn.click();
                    }
                });
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("shortcut-dummy", "data"),
        Input("play-interval", "n_intervals")
    )

    # Theme store: pure Python — toggles "dark"/"light" string in dcc.Store
    @app.callback(
        Output("theme-store", "data"),
        Input("btn-theme", "n_clicks"),
        State("theme-store", "data"),
        prevent_initial_call=True,
    )
    def toggle_theme_store(n, current):
        return "light" if (current or "dark") == "dark" else "dark"

    # Theme className: clientside reads the store and applies body class
    app.clientside_callback(
        """
        function(theme) {
            var t = theme || 'dark';
            var cls = t === 'dark' ? 'theme-dark' : 'theme-light';
            if (document.body.className !== cls) {
                document.body.className = cls;
            }
            return cls;
        }
        """,
        Output("main-container", "className"),
        Input("theme-store", "data"),
    )

    # Toggle fullscreen clientside callback (safe, no undefined)
    app.clientside_callback(
        """
        function(n_clicks) {
            if (!n_clicks) return window.dash_clientside.no_update;
            var panel = document.getElementById('center-graph-panel');
            if (panel) {
                panel.classList.toggle('fullscreen-active');
            }
            return window.dash_clientside.no_update;
        }
        """,
        Output("btn-fullscreen", "className"),
        Input("btn-fullscreen", "n_clicks")
    )

    # Binary upload → analysis pipeline (Triggers background thread)
    @app.callback(
        Output("upload-status",      "children"),
        Output("cfg-store",          "data"),
        Output("cg-store",           "data"),
        Output("trace-store",        "data"),
        Output("metrics-store",      "data"),
        Output("binary-info-store",  "data"),
        Output("vuln-store",         "data"),
        Output("analysis-id-store",  "data"),
        Output("console-interval",   "disabled"),
        Input("upload-binary",       "contents"),
        State("upload-binary",       "filename"),
        prevent_initial_call=True,
    )
    def handle_upload(contents, filename):
        if not contents:
            raise PreventUpdate

        try:
            _, b64 = contents.split(",", 1)
            decoded = base64.b64decode(b64)

            # ── Guard: file size limit (50 MB) ────────────────────────────────
            MAX_BYTES = 50 * 1024 * 1024  # 50 MB
            if len(decoded) > MAX_BYTES:
                return (
                    f"❌ Binary too large ({len(decoded) // (1024*1024)} MB). "
                    f"Maximum allowed size is 50 MB.",
                    [], [], [], {}, {}, [], None, True,
                )

            # ── Guard: require at least 4 bytes for magic-byte check ──────────
            if len(decoded) < 4:
                return (
                    "❌ File too small to be a valid binary.",
                    [], [], [], {}, {}, [], None, True,
                )

            # ── Guard: basic magic-byte validation (ELF / PE / Mach-O) ───────
            MAGIC_BYTES = [
                b"\x7fELF",            # ELF (Linux / Android / *BSD)
                b"MZ",                 # PE (Windows)
                b"\xfe\xed\xfa\xce",   # Mach-O 32-bit BE
                b"\xfe\xed\xfa\xcf",   # Mach-O 64-bit BE
                b"\xce\xfa\xed\xfe",   # Mach-O 32-bit LE
                b"\xcf\xfa\xed\xfe",   # Mach-O 64-bit LE
                b"\xca\xfe\xba\xbe",   # Mach-O FAT binary
            ]
            if not any(decoded[:len(m)] == m for m in MAGIC_BYTES):
                return (
                    f"❌ '{filename}' does not appear to be a valid ELF / PE / Mach-O binary. "
                    f"Got magic bytes: {decoded[:4].hex()}",
                    [], [], [], {}, {}, [], None, True,
                )

            analysis_id = str(uuid.uuid4())
            with ACTIVE_ANALYSES_LOCK:
                ACTIVE_ANALYSES[analysis_id] = {
                    "status": "running",
                    "backend": None,
                    "logs": [
                        {
                            "ts": time.time(),
                            "level": "INIT",
                            "msg": f"Initialising background worker for '{filename}'..."
                        }
                    ],
                    "result": None,
                    "error_msg": None
                }

            # Start worker thread
            t = threading.Thread(
                target=run_analysis_worker,
                args=(analysis_id, decoded, filename),
                daemon=True
            )
            t.start()

            return (
                html.Div([
                    html.Span("⚡  ", style={"animation": "blink 1s infinite"}),
                    html.Span(f"Initialising symbolic analysis for {filename}...")
                ]),
                [], [], [], {}, {}, [],
                analysis_id,
                False  # disabled=False (enable polling interval)
            )

        except Exception as exc:
            return (
                f"❌ Error starting analysis: {exc}",
                [], [], [], {}, {}, [],
                None,
                True  # disabled=True
            )

    # ── Console Polling Callback ──────────────────────────────────────────────
    @app.callback(
        Output("upload-status",      "children", allow_duplicate=True),
        Output("cfg-store",          "data",     allow_duplicate=True),
        Output("cg-store",           "data",     allow_duplicate=True),
        Output("trace-store",        "data",     allow_duplicate=True),
        Output("metrics-store",      "data",     allow_duplicate=True),
        Output("binary-info-store",  "data",     allow_duplicate=True),
