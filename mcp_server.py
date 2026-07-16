#!/usr/bin/env python3
"""ark MCP server -- lets any MCP client (Claude Code, Claude Desktop, ...)
drive the salvage tool: scan a codebase, build the ark, verify it, and get
the safe-to-delete verdict.

Wire into Claude Code (.mcp.json):
    {"mcpServers": {"ark": {"command": "python",
                            "args": ["C:/Users/USER/ark/mcp_server.py"]}}}

Protocol: MCP over stdio (newline-delimited JSON-RPC 2.0). Stdlib only.
Long operations (scan/build/verify) run as background jobs -- start one,
then poll ark_job until state != running.
"""
import json, sys, threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import ark

PROTO_FALLBACK = "2024-11-05"


# ------------------------------------------------------------------ tools ----
def t_scan(args):
    path = args["path"]
    job = ark.run_job("scan", lambda log: _strip(ark.scan(path, log=log)))
    return f"scan started as job {job.id} on {path}. Poll ark_job until state != 'running'; the result is the classification report."


def t_build(args):
    path = args["path"]
    out = args.get("out") or str(Path(path).resolve().parent / (Path(path).resolve().name + "-ark"))
    hs = bool(args.get("hash_source", False))
    def work(log):
        p = ark.plan(path, exclude=args.get("exclude") or (), log=log)
        return ark.build(path, out, p, hash_source=hs, log=log)
    job = ark.run_job("build", work)
    return (f"build started as job {job.id}: salvaging {path} -> {out} "
            f"(hash_source={hs}). Poll ark_job; this copies real data and can take minutes.")


def t_verify(args):
    ark_dir = args["ark_dir"]
    job = ark.run_job("verify", lambda log: ark.verify(ark_dir, log=log))
    return f"verify started as job {job.id} on {ark_dir}. Poll ark_job."


def t_job(args):
    job = ark.JOBS.get(args.get("id", "")) or ark._CURRENT["job"]
    if not job:
        return json.dumps({"state": "no job has run yet"})
    return json.dumps(job.snapshot(tail=int(args.get("log_tail", 25))), indent=1)


def t_status(args):
    lines = []
    res = ark.status(args["path"], args.get("ark_dir"), log=lines.append)
    return "\n".join(lines) + "\n\n" + json.dumps(res)


def _strip(scan_d):
    d = {k: v for k, v in scan_d.items() if k != "save_list"}
    d["biggest"] = d["biggest"][:30]
    return d


TOOLS = {
    "ark_scan": {
        "description": ("Read-only scan of a codebase: classifies every file as git-tracked / "
                        "re-fetchable (venvs, caches, downloaded model weights) / IRREPLACEABLE "
                        "(secrets, outputs, data, locally-trained weights), and reports git state, "
                        "gitlink landmines and nested repos. Starts a background job; poll ark_job."),
        "schema": {"type": "object", "properties": {
            "path": {"type": "string", "description": "absolute path of the codebase"}},
            "required": ["path"]},
        "fn": t_scan},
    "ark_build": {
        "description": ("Build the ark (the salvage): git bundle + uncommitted patch + copy of every "
                        "irreplaceable file (structure preserved) + restore-hints.md + SHA-256 manifests. "
                        "Background job; poll ark_job. Set hash_source true to fingerprint the whole "
                        "source tree for byte-exact rebuild proof (slow on huge trees)."),
        "schema": {"type": "object", "properties": {
            "path": {"type": "string"},
            "out": {"type": "string", "description": "ark output dir (default <name>-ark beside the source)"},
            "hash_source": {"type": "boolean"},
            "exclude": {"type": "array", "items": {"type": "string"},
                        "description": "glob patterns to leave out of the save set"}},
            "required": ["path"]},
        "fn": t_build},
    "ark_verify": {
        "description": "Re-hash an existing ark folder against its selfcheck manifest: did the backup survive transport/bit-rot? Background job; poll ark_job.",
        "schema": {"type": "object", "properties": {"ark_dir": {"type": "string"}},
                   "required": ["ark_dir"]},
        "fn": t_verify},
    "ark_job": {
        "description": "Status + log tail of the current (or a specific) background ark job. Poll until state != 'running'; 'result' then holds the full report.",
        "schema": {"type": "object", "properties": {
            "id": {"type": "string"}, "log_tail": {"type": "integer"}}},
        "fn": t_job},
    "ark_status": {
        "description": "The safe-to-delete checklist for a codebase (git pushed? uncommitted? loose files? landmines? ark built?). Fast, synchronous.",
        "schema": {"type": "object", "properties": {
            "path": {"type": "string"}, "ark_dir": {"type": "string"}},
            "required": ["path"]},
        "fn": t_status},
}


# ------------------------------------------------------------------ rpc ------
def _send(obj):
    sys.stdout.buffer.write(json.dumps(obj, ensure_ascii=False).encode("utf-8") + b"\n")
    sys.stdout.buffer.flush()


def _result(id_, result):
    _send({"jsonrpc": "2.0", "id": id_, "result": result})


def _error(id_, code, msg):
    _send({"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": msg}})


def serve():
    for raw in sys.stdin.buffer:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw.decode("utf-8"))
        except ValueError:
            continue
        mid, method = msg.get("id"), msg.get("method", "")
        params = msg.get("params") or {}
        if method == "initialize":
            _result(mid, {"protocolVersion": params.get("protocolVersion", PROTO_FALLBACK),
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "ark", "version": ark.ARK_VERSION}})
        elif method == "tools/list":
            _result(mid, {"tools": [{"name": k, "description": v["description"],
                                     "inputSchema": v["schema"]} for k, v in TOOLS.items()]})
        elif method == "tools/call":
            name = params.get("name", "")
            tool = TOOLS.get(name)
            if not tool:
                _error(mid, -32602, f"unknown tool {name}")
                continue
            try:
                text = tool["fn"](params.get("arguments") or {})
                _result(mid, {"content": [{"type": "text", "text": text}], "isError": False})
            except Exception as ex:                    # noqa: BLE001
                _result(mid, {"content": [{"type": "text", "text": f"error: {ex}"}], "isError": True})
        elif method == "ping":
            _result(mid, {})
        elif mid is not None:                          # unknown request
            _error(mid, -32601, f"method not found: {method}")
        # notifications (no id): ignore


if __name__ == "__main__":
    serve()
