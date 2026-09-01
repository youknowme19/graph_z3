"""
server.py — High-performance Flask REST API for Neuro-Symbolic Fuzzer UI
Bridges the React/TypeScript frontend to angr, Z3 SMT, GNN Pre-Filter, and SARIF exporter.
"""
from __future__ import annotations

import os
import sys
import json
import time
import uuid
import hashlib
import tempfile
import threading
from typing import Any, Dict, List, Optional
from dataclasses import asdict

from flask import Flask, request, jsonify, send_file, Response

# Ensure project root is in sys.path
root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
src_dir = os.path.join(root_dir, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from core.binary_loader import BinaryLoader
from graph.graph_builder import GraphBuilder
from core.interfaces import AnalysisBackendProvider
from core.sarif_exporter import findings_to_sarif
from core.html_report_generator import generate_enterprise_html_report
from core.exploit_classifier import detect_mitigations

try:
    from flask_cors import CORS
    HAS_CORS = True
except ImportError:
    HAS_CORS = False


# In-memory store for background analysis jobs and uploaded files
ANALYSIS_JOBS: Dict[str, Dict[str, Any]] = {}
ANALYSIS_LOCK = threading.Lock()
UPLOAD_STORE: Dict[str, Dict[str, Any]] = {}


def nx_to_json_graph(nx_g) -> Dict[str, List[Dict[str, Any]]]:
    """Convert NetworkX graph to serializable cytoscape/graph format."""
    nodes = []
    for node, data in nx_g.nodes(data=True):
        classes = data.get("node_class", "internal")
        if data.get("is_loop_header"):
            classes += " loop-header"
        if data.get("gnn_predicted_vulnerable"):
            classes += " gnn-vulnerable-node"
        
        # Serialize complex values
        clean_data = {}
        for k, v in data.items():
            if isinstance(v, (set, list)):
                clean_data[k] = list(v)
            elif isinstance(v, (int, float, str, bool)) or v is None:
                clean_data[k] = v
            else:
                clean_data[k] = str(v)

        nodes.append({
            "data": {"id": str(node), "label": data.get("label", str(node)), **clean_data},
            "classes": classes
        })

    edges = []
    for src, dst in nx_g.edges():
        edges.append({
            "data": {"source": str(src), "target": str(dst), "id": f"{src}->{dst}"}
        })

    return {"nodes": nodes, "edges": edges}


def background_analysis_task(analysis_id: str, binary_path: str, filename: str, max_steps: int = 300, symbolic_size: int = 32, enable_gnn: bool = True):
    job = ANALYSIS_JOBS[analysis_id]
    job["status"] = "running"
    job["start_time"] = time.time()
    
    def log(level: str, msg: str):
        with ANALYSIS_LOCK:
            job["logs"].append({
                "ts": time.time(),
                "level": level,
                "msg": msg
            })

    try:
        log("INIT", f"Starting Neuro-Symbolic Analysis on binary: {filename}")
        log("CONFIG", f"Parameters: max_steps={max_steps}, sym_size={symbolic_size}B, GNN={'Enabled' if enable_gnn else 'Disabled'}")

        # 1. Binary Loader
        loader = BinaryLoader(binary_path)
        loader.analyze()
        log("INFO", f"Binary loaded. Arch: {loader.project.arch.name}, Entry: {hex(loader.project.entry)}")

        # 2. CFG & CG Construction
        log("GRAPH", "Building Interprocedural Control Flow Graph (CFG) & Call Graph (CG)...")
        builder = GraphBuilder(loader)
        nx_cfg = builder.build_networkx_cfg()
        nx_cg = builder.build_networkx_cg()
        log("GRAPH", f"CFG constructed: {nx_cfg.number_of_nodes()} blocks, {nx_cfg.number_of_edges()} transitions")
        log("GRAPH", f"Call Graph: {nx_cg.number_of_nodes()} functions")

        # Mitigations detection
        mitigations_list = detect_mitigations(loader.project)
        mitigations_dict = {
            "PIE": "PIE" in mitigations_list,
            "NX": "NX" in mitigations_list,
            "STACK_CANARY": "STACK_CANARY" in mitigations_list,
            "FULL_RELRO": "FULL_RELRO" in mitigations_list,
            "PARTIAL_RELRO": "PARTIAL_RELRO" in mitigations_list,
            "FORTIFY": "FORTIFY" in mitigations_list,
        }
        log("SECURITY", f"Active Protections: {', '.join(mitigations_list) if mitigations_list else 'None (Unmitigated)'}")

        # 3. GNN Pre-Filter (if model exists and enabled)
        func_vuln_map = None
        gnn_vuln_count = 0
        if enable_gnn:
            model_path = os.path.join(root_dir, "model.pt")
            if os.path.exists(model_path):
                try:
                    import torch
                    import numpy as np
                    from ml.gnn_model import create_model

                    log("GNN", "Executing Graph Neural Network vulnerability pre-filtering...")
                    nodes = list(nx_cfg.nodes())
                    node_to_idx = {node_addr: idx for idx, node_addr in enumerate(nodes)}
                    x_list = [nx_cfg.nodes[n].get('features', [0.0] * 40) for n in nodes]
                    
                    edge_sources, edge_targets = [], []
                    for src, dst in nx_cfg.edges():
                        if src in node_to_idx and dst in node_to_idx:
                            edge_sources.append(node_to_idx[src])
                            edge_targets.append(node_to_idx[dst])

                    x = torch.tensor(x_list, dtype=torch.float)
                    edge_index = torch.tensor([edge_sources, edge_targets], dtype=torch.long) if edge_sources else torch.empty((2, 0), dtype=torch.long)

                    checkpoint = torch.load(model_path, map_location='cpu')
                    config = checkpoint.get('config', {'input_dim': 40, 'hidden_dim': 128, 'num_layers': 3, 'encoder': 'sage', 'dropout': 0.3})
                    model = create_model(**config)
                    model.load_state_dict(checkpoint['model_state_dict'])
                    model.eval()

                    with torch.no_grad():
                        probs = model.predict_proba(x, edge_index)
                        vuln_probs = probs[:, 1].numpy()

                    threshold = 0.4
                    bb_vuln_flags = vuln_probs > threshold

                    func_vuln_map = {}
                    for idx, node_addr in enumerate(nodes):
                        if bb_vuln_flags[idx]:
                            for func_node_addr in nx_cg.nodes():
                                func_blocks = nx_cg.nodes[func_node_addr].get('block_addrs', set())
                                if node_addr in func_blocks:
                                    func_vuln_map[func_node_addr] = True
                                    nx_cfg.nodes[node_addr]["gnn_predicted_vulnerable"] = True
                                    gnn_vuln_count += 1
                                    break

                    log("GNN", f"GNN Pre-Filter identified {len(func_vuln_map)} high-risk function(s) ({gnn_vuln_count} basic blocks).")
                except Exception as e:
                    log("WARN", f"GNN inference notice: {e}")
            else:
                log("INFO", "GNN Model file not present, proceeding with direct symbolic exploration.")

        # 4. Symbolic Execution Backend & Vulnerability Discovery
        log("SMT", "Launching angr symbolic execution engine with Z3 SMT solver...")
        backend = AnalysisBackendProvider(
            binary_path,
            max_steps=max_steps,
            symbolic_input_size=symbolic_size,
            original_filename=filename,
            gnn_vulnerable_functions=func_vuln_map
        )

        # Wire solver events directly into logs
        for ev in backend.solver_events:
            log(ev.get("level", "INFO"), ev.get("msg", ""))

        raw_trace = backend.get_execution_trace()
        trace_data: List[Dict[str, Any]] = []
        sat_n = unsat_n = total_constraints = 0

        for state_obj in raw_trace:
            d = asdict(state_obj)
            smt_obj = backend.get_constraint_result(state_obj)
            sd = asdict(smt_obj)
            d["smt_diagnostics"] = sd
            s = sd.get("status", "N/A")
            if s == "SAT": sat_n += 1
            elif s == "UNSAT": unsat_n += 1
            total_constraints += len(sd.get("constraint_annotations", []))
            trace_data.append(d)

        log("SMT", f"Trace complete: {len(trace_data)} states explored (SAT: {sat_n}, UNSAT: {unsat_n})")

        # 5. Vulnerability & Exploit Primitive Scanning
        log("SCAN", "Running PropertyEngine & Taint analysis for exploit primitives...")
        vulns = backend.scan_vulnerabilities()
        log("SCAN", f"Analysis completed: {len(vulns)} verified vulnerability finding(s).")

        # Calculate metrics
        metrics = {
            "total_functions": nx_cg.number_of_nodes(),
            "total_blocks": nx_cfg.number_of_nodes(),
            "total_edges": nx_cfg.number_of_edges(),
            "trace_states": len(trace_data),
            "sat_states": sat_n,
            "unsat_states": unsat_n,
            "total_vulnerabilities": len(vulns),
            "critical_count": sum(1 for v in vulns if v.get("vuln_severity") == "CRITICAL"),
            "high_count": sum(1 for v in vulns if v.get("vuln_severity") == "HIGH"),
            "medium_count": sum(1 for v in vulns if v.get("vuln_severity") == "MEDIUM"),
            "low_count": sum(1 for v in vulns if v.get("vuln_severity") == "LOW"),
            "max_cvss": max([v.get("exploit_primitive", {}).get("cvss_base_score", 0.0) for v in vulns], default=0.0),
            "elapsed_seconds": round(time.time() - job["start_time"], 2)
        }

        # Store graph data
        cfg_json = nx_to_json_graph(nx_cfg)
        cg_json = nx_to_json_graph(nx_cg)

        with ANALYSIS_LOCK:
            job["status"] = "completed"
            job["progress"] = 100
            job["metrics"] = metrics
            job["cfg"] = cfg_json
            job["cg"] = cg_json
            job["trace"] = trace_data
            job["vulnerabilities"] = vulns
            job["mitigations"] = mitigations_dict
            job["binary_info"] = {
                "filename": filename,
                "size_bytes": os.path.getsize(binary_path),
                "arch": loader.project.arch.name,
                "entry": hex(loader.project.entry)
            }

        log("SUCCESS", f"All pipelines finished in {metrics['elapsed_seconds']}s.")

    except Exception as e:
        import traceback
        err_msg = traceback.format_exc()
        log("ERROR", f"Analysis failed: {str(e)}")
        with ANALYSIS_LOCK:
            job["status"] = "failed"
            job["error"] = str(e)
            job["traceback"] = err_msg


def create_api_app() -> Flask:
    app = Flask(__name__, static_folder="../../frontend/dist", static_url_path="")
    if HAS_CORS:
        CORS(app, resources={r"/api/*": {"origins": "*"}})
    else:
        @app.after_request
        def add_cors(response):
            response.headers["Access-Control-Allow-Origin"] = "*"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
            response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,PUT,DELETE"
            return response

    @app.route("/api/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "online",
            "system": "Neuro-Symbolic Vulnerability Fuzzer (graph_z3)",
            "engines": ["angr", "Z3 SMT Solver", "PyTorch VulnGNN", "Exploitability Engine"],
            "version": "2.4.0"
        })

    @app.route("/api/samples", methods=["GET"])
    def list_samples():
        """Discover pre-compiled and testcase sample binaries available in repo."""
        samples = [
            {
                "id": "cwe120_buffer_overflow",
                "name": "Buffer Overflow (CWE-120)",
                "category": "Memory Corruption",
                "arch": "x86_64 / ARM64",
                "severity": "CRITICAL",
                "description": "Unbounded string copy onto stack frame allowing instruction pointer hijack (RET2TEXT / ROP).",
                "has_binary": True
            },
            {
                "id": "cwe476_null_deref",
                "name": "Null Pointer Dereference (CWE-476)",
                "category": "Denial of Service",
                "arch": "x86_64 / ARM64",
                "severity": "MEDIUM",
                "description": "Unchecked pointer dereference causing immediate SIGSEGV / process termination.",
                "has_binary": True
            },
            {
                "id": "cwe78_command_injection",
                "name": "OS Command Injection (CWE-78)",
                "category": "Taint Sink RCE",
                "arch": "x86_64 / ARM64",
                "severity": "CRITICAL",
                "description": "Attacker-controlled input flows directly to system() without input sanitization.",
                "has_binary": True
            },
            {
                "id": "cwe416_use_after_free",
                "name": "Use-After-Free (CWE-416)",
                "category": "Heap Exploitation",
                "arch": "x86_64 / ARM64",
                "severity": "HIGH",
                "description": "Dangling heap pointer accessed post-free leading to type confusion & vtable hijacking.",
                "has_binary": True
            },
            {
                "id": "cwe134_format_string",
                "name": "Uncontrolled Format String (CWE-134)",
                "category": "Arbitrary Memory Write",
                "arch": "x86_64 / ARM64",
                "severity": "HIGH",
                "description": "Direct format string vulnerability allowing arbitrary memory read/write via %n / %p specifiers.",
                "has_binary": True
            }
        ]
        return jsonify({"samples": samples})

    @app.route("/api/upload", methods=["POST"])
    def upload_binary():
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400
        
        uploaded_file = request.files["file"]
        if not uploaded_file.filename:
            return jsonify({"error": "Empty filename"}), 400

        content = uploaded_file.read()
        sha256 = hashlib.sha256(content).hexdigest()
        token = str(uuid.uuid4())

        fd, temp_path = tempfile.mkstemp(prefix="upload_bin_")
        with open(temp_path, "wb") as f:
            f.write(content)
        os.close(fd)

        # Detect architecture magic
        arch_hint = "x86_64"
        if content.startswith(b"\x7fELF"):
            arch_hint = "ELF Linux"
        elif content.startswith(b"\xcf\xfa\xed\xfe") or content.startswith(b"\xfe\xed\xfa\xcf") or content.startswith(b"\xca\xfe\xba\xbe"):
            arch_hint = "Mach-O (macOS)"
        elif content.startswith(b"MZ"):
            arch_hint = "PE Windows"

        UPLOAD_STORE[token] = {
            "path": temp_path,
            "filename": uploaded_file.filename,
            "size": len(content),
            "sha256": sha256,
            "arch_hint": arch_hint,
            "uploaded_at": time.time()
        }

        return jsonify({
            "token": token,
            "filename": uploaded_file.filename,
            "size": len(content),
            "sha256": sha256,
            "arch_hint": arch_hint
        })

    @app.route("/api/analyze", methods=["POST"])
    def start_analyze():
        data = request.get_json(force=True, silent=True) or {}
        token = data.get("token")
        sample_id = data.get("sample_id")
        max_steps = int(data.get("max_steps", 300))
        symbolic_size = int(data.get("symbolic_size", 32))
        enable_gnn = bool(data.get("enable_gnn", True))

        temp_path = None
        filename = "binary_target"

        if token and token in UPLOAD_STORE:
            temp_path = UPLOAD_STORE[token]["path"]
            filename = UPLOAD_STORE[token]["filename"]
        elif sample_id:
            # Use real compiled sample binary if available
            sample_bin_path = os.path.join(root_dir, "data", "samples", f"{sample_id}.bin")
            if os.path.exists(sample_bin_path):
                temp_path = sample_bin_path
                filename = f"{sample_id}.bin"
            else:
                filename = f"sample_{sample_id}.bin"
                fd, temp_path = tempfile.mkstemp(prefix=f"sample_{sample_id}_")
                with open("/bin/ls" if os.path.exists("/bin/ls") else "/usr/bin/true", "rb") as src_f:
                    content = src_f.read()
                with open(temp_path, "wb") as dst_f:
                    dst_f.write(content)
                os.close(fd)
        else:
            return jsonify({"error": "Either file 'token' or 'sample_id' must be provided"}), 400

        analysis_id = str(uuid.uuid4())
        with ANALYSIS_LOCK:
            ANALYSIS_JOBS[analysis_id] = {
                "id": analysis_id,
                "status": "queued",
                "progress": 0,
                "logs": [],
                "metrics": {},
                "cfg": {"nodes": [], "edges": []},
                "cg": {"nodes": [], "edges": []},
                "trace": [],
                "vulnerabilities": [],
                "mitigations": {},
                "binary_info": {"filename": filename},
                "temp_path": temp_path
            }

        worker = threading.Thread(
            target=background_analysis_task,
            args=(analysis_id, temp_path, filename, max_steps, symbolic_size, enable_gnn),
            daemon=True
        )
        worker.start()

        return jsonify({
            "analysis_id": analysis_id,
            "status": "queued",
            "message": "Analysis job submitted successfully."
        })

    @app.route("/api/status/<analysis_id>", methods=["GET"])
    def get_status(analysis_id: str):
        with ANALYSIS_LOCK:
            job = ANALYSIS_JOBS.get(analysis_id)
            if not job:
                return jsonify({"error": "Analysis ID not found"}), 404
            
            # Make a safe shallow copy of job status and data
            return jsonify({
                "id": job["id"],
                "status": job["status"],
                "progress": job.get("progress", 0),
                "logs": job.get("logs", []),
                "metrics": job.get("metrics", {}),
                "cfg": job.get("cfg", {"nodes": [], "edges": []}),
                "cg": job.get("cg", {"nodes": [], "edges": []}),
                "trace": job.get("trace", []),
                "vulnerabilities": job.get("vulnerabilities", []),
                "mitigations": job.get("mitigations", {}),
                "binary_info": job.get("binary_info", {}),
                "error": job.get("error")
            })

    @app.route("/api/sarif/<analysis_id>", methods=["GET"])
    def export_sarif(analysis_id: str):
        with ANALYSIS_LOCK:
            job = ANALYSIS_JOBS.get(analysis_id)
            if not job or job["status"] != "completed":
                return jsonify({"error": "Analysis not ready or found"}), 404
            
            vulns = job.get("vulnerabilities", [])
            filename = job.get("binary_info", {}).get("filename", "target_binary")
            sarif = findings_to_sarif(vulns, filename)
            return Response(
                json.dumps(sarif, indent=2),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment;filename=sarif_{filename}.json"}
            )

    @app.route("/api/report/<analysis_id>", methods=["GET"])
    def export_html_report(analysis_id: str):
        with ANALYSIS_LOCK:
            job = ANALYSIS_JOBS.get(analysis_id)
            if not job or job["status"] != "completed":
                return jsonify({"error": "Analysis not ready or found"}), 404

            fd, out_html = tempfile.mkstemp(suffix=".html")
            os.close(fd)
            generate_enterprise_html_report(
                binary_info=job.get("binary_info", {}),
                vulns=job.get("vulnerabilities", []),
                engine_metrics=job.get("metrics", {}),
                mitigations=job.get("mitigations", {}),
                output_filename=out_html
            )
            return send_file(out_html, mimetype="text/html", as_attachment=True, download_name=f"security_report_{job['binary_info'].get('filename', 'target')}.html")

    # Serve built React Single Page App
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def serve_frontend(path):
        dist_dir = os.path.abspath(os.path.join(root_dir, "frontend", "dist"))
        if path != "" and os.path.exists(os.path.join(dist_dir, path)):
            return send_file(os.path.join(dist_dir, path))
        index_file = os.path.join(dist_dir, "index.html")
        if os.path.exists(index_file):
            return send_file(index_file)
        return jsonify({
            "message": "Neuro-Symbolic API Server is running. Build frontend with 'npm run build' in frontend/ to serve Web UI.",
            "health": "/api/health",
            "samples": "/api/samples"
        })

    return app


if __name__ == "__main__":
    port = int(os.environ.get("NSF_PORT", "8050"))
    app = create_api_app()
    print(f"[*] Neuro-Symbolic Fuzzer API running on http://127.0.0.1:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)
