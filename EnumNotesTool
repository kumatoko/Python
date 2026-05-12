import os
import json
import datetime
from flask import Flask, render_template, request, jsonify, send_file
import io

app = Flask(__name__)

SAVES_DIR = os.path.join(os.path.dirname(__file__), "saves")
os.makedirs(SAVES_DIR, exist_ok=True)


@app.route("/")
def index():
    saves = []
    for f in sorted(os.listdir(SAVES_DIR), reverse=True):
        if f.endswith(".json"):
            saves.append(f[:-5])
    return render_template("index.html", saves=saves)


@app.route("/api/save", methods=["POST"])
def save():
    data = request.json
    name = data.get("name", "").strip()
    if not name:
        name = data.get("target_ip", "unknown").replace(".", "_") or "unknown"
    filename = f"{name}.json"
    path = os.path.join(SAVES_DIR, filename)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    saves = [fn[:-5] for fn in sorted(os.listdir(SAVES_DIR), reverse=True) if fn.endswith(".json")]
    return jsonify({"ok": True, "name": name, "saves": saves})


@app.route("/api/load/<name>")
def load(name):
    path = os.path.join(SAVES_DIR, f"{name}.json")
    if not os.path.exists(path):
        return jsonify({"error": "Not found"}), 404
    with open(path) as f:
        return jsonify(json.load(f))


@app.route("/api/delete/<name>", methods=["DELETE"])
def delete(name):
    path = os.path.join(SAVES_DIR, f"{name}.json")
    if os.path.exists(path):
        os.remove(path)
    saves = [fn[:-5] for fn in sorted(os.listdir(SAVES_DIR), reverse=True) if fn.endswith(".json")]
    return jsonify({"ok": True, "saves": saves})


@app.route("/api/export_md", methods=["POST"])
def export_md():
    data = request.json
    md = build_markdown(data)
    buf = io.BytesIO(md.encode("utf-8"))
    ip = data.get("target_ip", "target").replace(".", "_") or "target"
    filename = f"enum_{ip}_{datetime.date.today()}.md"
    return send_file(buf, as_attachment=True, download_name=filename, mimetype="text/markdown")


@app.route("/api/saves")
def list_saves():
    saves = [fn[:-5] for fn in sorted(os.listdir(SAVES_DIR), reverse=True) if fn.endswith(".json")]
    return jsonify(saves)


def build_markdown(data):
    ip = data.get("target_ip", "Unknown")
    status = data.get("status", "todo")
    status_label = {"todo": "To do", "inprog": "In progress", "done": "Completed"}.get(status, status)
    date = datetime.date.today().isoformat()

    lines = [
        f"# Enumeration notes — {ip}",
        f"",
        f"**Status:** {status_label}  ",
        f"**Date:** {date}",
        f"",
        f"## Target info",
        f"",
        f"| Field | Value |",
        f"|---|---|",
        f"| IP | {ip} |",
    ]
    for field, key in [("OS", "os"), ("Hostname", "hostname"), ("Domain", "domain"),
                        ("Kernel", "kernel"), ("Current user", "current_user")]:
        v = data.get(key, "").strip()
        if v:
            lines.append(f"| {field} | {v} |")

    info_notes = data.get("info_notes", "").strip()
    if info_notes:
        lines += ["", info_notes]

    lines += ["", "## Open ports", ""]
    ports = data.get("ports", [])
    if ports:
        lines.append("| Port | Protocol | Service / version | Status |")
        lines.append("|---|---|---|---|")
        for p in ports:
            if p.get("port"):
                lines.append(f"| {p.get('port','')} | {p.get('proto','TCP')} | {p.get('service','')} | {p.get('status','open')} |")
    else:
        lines.append("_None recorded_")

    lines += ["", "## Credentials found", ""]
    creds = data.get("creds", [])
    if creds:
        lines.append("| Username | Password / hash | Service |")
        lines.append("|---|---|---|")
        for c in creds:
            if c.get("user"):
                lines.append(f"| {c.get('user','')} | {c.get('pass','')} | {c.get('service','')} |")
    else:
        lines.append("_None found_")

    lines += ["", "## Vulnerabilities", ""]
    vulns = data.get("vulns", [])
    if vulns:
        lines.append("| Vulnerability / CVE | Severity | Exploited |")
        lines.append("|---|---|---|")
        for v in vulns:
            if v.get("name"):
                exp = {"yes": "Yes", "attempt": "Attempted", "no": "No"}.get(v.get("exploited", "no"), "No")
                lines.append(f"| {v.get('name','')} | {v.get('severity','Medium')} | {exp} |")
    else:
        lines.append("_None identified_")

    lines += ["", "## Exploitation path", ""]
    for label, key in [("Initial foothold", "foothold"), ("Privesc method", "privesc"), ("Proof / flag", "flag")]:
        v = data.get(key, "").strip()
        if v:
            lines.append(f"**{label}:** {v}  ")

    commands = data.get("commands", "").strip()
    if commands:
        lines += ["", "```bash", commands, "```"]

    notes = data.get("notes", "").strip()
    if notes:
        lines += ["", "## General notes", "", notes]

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print("\n  Enum Notes running at http://127.0.0.1:5000\n")
    app.run(debug=False, port=5000)
