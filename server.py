#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import json
import time
import hmac
import logging
import subprocess
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, request, send_from_directory, render_template_string,
    jsonify, abort, Response, redirect
)
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash

# =========================
# Paths / Config
# =========================
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = (BASE_DIR / "data").resolve()
USERS_DB = (BASE_DIR / "users.json").resolve()

HOST = "0.0.0.0"
PORT = 8443

CERT_FILE = (BASE_DIR / "cert.pem").resolve()
KEY_FILE  = (BASE_DIR / "key.pem").resolve()
AUDIT_LOG = (BASE_DIR / "audit.log").resolve()

# Security limits
ALLOWED_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".txt", ".log", ".pcap", ".pcapng", ".csv", ".pdf", ".json"}
MAX_CONTENT_LENGTH = 200 * 1024 * 1024  # 200MB

# Network ACL (optional)
# 留空代表不做精準 IP 限制；你目前在 LAN 測試建議至少用 prefixes
ALLOWED_IPS = set()                 # e.g. {"192.168.17.103"}
ALLOWED_PREFIXES = {"192.168."}     # e.g. {"192.168.", "10.0."}; empty set => allow all

# =========================
# App init
# =========================
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    filename=str(AUDIT_LOG),
    level=logging.INFO,
    format="%(asctime)s %(message)s"
)

# =========================
# TLS helper: auto-generate
# =========================
def ensure_tls_cert():
    """
    If cert.pem/key.pem missing, generate self-signed cert for LAN usage.
    """
    if CERT_FILE.exists() and KEY_FILE.exists():
        return

    # Generate with openssl
    # CN does not matter for most LAN use; browser trust still requires import to Keychain.
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(KEY_FILE), "-out", str(CERT_FILE),
        "-days", "365", "-nodes",
        "-subj", "/CN=lan-fileserver"
    ]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # tighten key permissions a bit
        os.chmod(KEY_FILE, 0o600)
    except Exception as e:
        raise SystemExit(f"[ERR] Failed to generate TLS cert/key via openssl: {e}")

# =========================
# Auth / ACL helpers
# =========================
def client_ip() -> str:
    return request.remote_addr or "-"

def ip_allowed(ip: str) -> bool:
    if not ip or ip == "-":
        return False
    if ALLOWED_IPS:
        return ip in ALLOWED_IPS
    if ALLOWED_PREFIXES:
        return any(ip.startswith(p) for p in ALLOWED_PREFIXES)
    return True

def load_users():
    if not USERS_DB.exists():
        return {}
    with open(USERS_DB, "r", encoding="utf-8") as f:
        return json.load(f)

def authenticate(username: str, password: str) -> bool:
    users = load_users()
    user = users.get(username)
    if not user:
        return False
    return check_password_hash(user.get("password_hash", ""), password)

def check_basic_auth() -> bool:
    auth = request.authorization
    if not auth:
        return False
    return authenticate(auth.username or "", auth.password or "")

def authed_username() -> str:
    auth = request.authorization
    return (auth.username if auth and auth.username else "-")

def require_auth():
    ip = client_ip()
    if not ip_allowed(ip):
        abort(403, description="Forbidden (IP not allowed)")

    if not check_basic_auth():
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="LAN-File-Server"'}
        )
    return None

# =========================
# File safety helpers
# =========================
def ext_allowed(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTS

def safe_join_data(filename: str) -> Path:
    """
    Prevent path traversal; only allow within DATA_DIR.
    """
    cleaned = secure_filename(filename)
    if not cleaned:
        abort(400, description="Invalid filename")
    target = (DATA_DIR / cleaned).resolve()
    if DATA_DIR not in target.parents and target != DATA_DIR:
        abort(400, description="Invalid path")
    return target

def atomic_write(path: Path, data: bytes):
    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{int(time.time())}")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)

def wants_html():
    accept = request.headers.get("Accept", "")
    return "text/html" in accept

# =========================
# Security headers
# =========================
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    return resp

# =========================
# Audit logging (includes username)
# =========================
@app.after_request
def audit_log(resp):
    ip = client_ip()
    user = authed_username()
    method = request.method
    path = request.path
    ua = request.headers.get("User-Agent", "-")
    status = resp.status_code
    length = resp.calculate_content_length()
    length_str = str(length) if length is not None else "-"
    logging.info(f'{ip} user="{user}" {method} {path} {status} bytes={length_str} UA="{ua}"')
    return resp

# =========================
# UI Template
# =========================
HTML = """
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8"/>
<title>LAN File Server</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif; margin: 20px; }
.container { display: flex; flex-wrap: wrap; gap: 14px; }
.card { width: 220px; border: 1px solid #ddd; border-radius: 10px; padding: 10px; }
.thumb { width: 200px; height: 200px; object-fit: cover; border: 1px solid #ccc; border-radius: 8px; }
.small { color: #666; font-size: 12px; word-break: break-all; }
.actions a { margin-right: 8px; font-size: 12px; }
hr { border: 0; border-top: 1px solid #eee; margin: 18px 0; }
</style>
</head>
<body>
<h2>LAN File Server</h2>

<div class="small">
Storage: {{ data_dir }}<br/>
Allowed extensions: {{ exts }}<br/>
Max upload size: {{ max_mb }} MB
</div>

<hr/>

<h3>Upload</h3>
<form action="/upload" method="post" enctype="multipart/form-data">
  <input type="file" name="file" required />
  <button type="submit">Upload</button>
</form>

<hr/>

<h3>Files</h3>
<div class="container">
{% for f in files %}
  <div class="card">
    {% if f.is_image %}
      <a href="/file/{{ f.name }}" target="_blank">
        <img class="thumb" src="/file/{{ f.name }}">
      </a>
    {% else %}
      <div class="thumb" style="display:flex;align-items:center;justify-content:center;">
        <div class="small">No preview</div>
      </div>
    {% endif %}
    <div class="small">{{ f.name }}</div>
    <div class="small">size: {{ f.size }} bytes</div>
    <div class="actions">
      <a href="/download/{{ f.name }}">download</a>
      <a href="/delete_ui/{{ f.name }}" onclick="return confirm('Delete {{ f.name }}?')">delete</a>
    </div>
  </div>
{% endfor %}
</div>

</body>
</html>
"""

def list_files():
    items = []
    for p in sorted(DATA_DIR.iterdir()):
        if p.is_file():
            ext = p.suffix.lower()
            items.append({
                "name": p.name,
                "size": p.stat().st_size,
                "is_image": ext in {".png", ".jpg", ".jpeg", ".gif"},
            })
    return items

# =========================
# Routes
# =========================
@app.route("/", methods=["GET"])
def index():
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    return render_template_string(
        HTML,
        files=list_files(),
        data_dir=str(DATA_DIR),
        exts=", ".join(sorted(ALLOWED_EXTS)),
        max_mb=int(MAX_CONTENT_LENGTH / (1024 * 1024))
    )

@app.route("/file/<path:filename>", methods=["GET"])
def get_file(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    if not ext_allowed(filename):
        abort(415, description="File type not allowed")
    return send_from_directory(str(DATA_DIR), filename, conditional=True)

@app.route("/download/<path:filename>", methods=["GET"])
def download(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    if not ext_allowed(filename):
        abort(415, description="File type not allowed")
    return send_from_directory(str(DATA_DIR), filename, as_attachment=True)

@app.route("/upload", methods=["POST"])
def upload():
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp

    if "file" not in request.files:
        abort(400, description="No file part")

    f = request.files["file"]
    if not f.filename:
        abort(400, description="Empty filename")

    if not ext_allowed(f.filename):
        abort(415, description="File type not allowed")

    filename = secure_filename(f.filename)
    target = safe_join_data(filename)
    f.save(str(target))

    # Browser UX: go back to list
    if wants_html():
        return redirect("/")
    return jsonify({"status": "uploaded", "file": filename}), 200

@app.route("/file/<path:filename>", methods=["PUT"])
def put_file(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp

    if not ext_allowed(filename):
        abort(415, description="File type not allowed")

    target = safe_join_data(filename)
    atomic_write(target, request.get_data())

    if wants_html():
        return redirect("/")
    return jsonify({"status": "updated", "file": target.name}), 200

@app.route("/file/<path:filename>", methods=["DELETE"])
def delete_file(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp

    target = safe_join_data(filename)
    if not target.exists():
        abort(404, description="Not found")

    target.unlink()

    if wants_html():
        return redirect("/")
    return jsonify({"status": "deleted", "file": target.name}), 200

# UI delete action (clickable)
@app.route("/delete_ui/<path:filename>", methods=["GET"])
def delete_ui(filename):
    auth_resp = require_auth()
    if auth_resp:
        return auth_resp
    target = safe_join_data(filename)
    if target.exists():
        target.unlink()
    return ("", 302, {"Location": "/"})

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat() + "Z"}), 200

# =========================
# Main
# =========================
if __name__ == "__main__":
    ensure_tls_cert()
    print(f"[INFO] Serving {DATA_DIR} on https://0.0.0.0:{PORT}")
    app.run(host=HOST, port=PORT,
        ssl_context=(str(CERT_FILE), str(KEY_FILE)),
        debug=True)

    #app.run(host=HOST, port=PORT, ssl_context=(str(CERT_FILE), str(KEY_FILE)))
