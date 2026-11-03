"""
Flask Application for Security Benchmarking - Basic SAST Cases (Python)
Realistic web application endpoints handling authentication, orders, documents, and diagnostics.
"""

import os
import re
import sys
import json
import yaml
import html
import random
import pickle
import secrets
import hashlib
import sqlite3
import subprocess
from urllib.parse import urlparse
from flask import Flask, request, jsonify, redirect, render_template_string
import requests
import jwt
from xml.etree import ElementTree as ET

app = Flask(__name__)
app.config['SECRET_KEY'] = 'development_only_secret_key_not_for_prod'
UPLOAD_DIR = "/tmp/app_storage/uploads"
BASE_DIR = "/tmp/app_storage"
ALLOWED_DOMAINS = {"api.internal.service", "partner.service.org"}
FEATURE_FLAG_DEBUG_EXEC = False


@app.route("/api/user/search", methods=["GET"])
def search_user():
    username = request.args.get("query", "")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # GT: id=SAST-PY-001 type=TP cwe=CWE-89 rule=sql-injection
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    results = cursor.fetchall()
    return jsonify(results=results)


@app.route("/api/user/profile", methods=["GET"])
def get_user_profile():
    user_id = request.args.get("id", "0")
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    # GT: id=SAST-PY-015 type=FP reason=parameterized-query
    cursor.execute("SELECT id, username, email FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    return jsonify(user=user)


@app.route("/api/system/ping", methods=["POST"])
def ping_host():
    host = request.json.get("host", "127.0.0.1")
    # GT: id=SAST-PY-002 type=TP cwe=CWE-78 rule=command-injection
    proc = subprocess.Popen(f"ping -c 1 {host}", shell=True, stdout=subprocess.PIPE)
    output, _ = proc.communicate()
    return jsonify(output=output.decode('utf-8', errors='replace'))


@app.route("/api/system/status", methods=["GET"])
def get_system_status():
    # GT: id=SAST-PY-018 type=FP reason=constant-argument-no-taint
    res = subprocess.run(["uptime"], capture_output=True, text=True, check=True)
    return jsonify(status=res.stdout)


@app.route("/api/documents/download", methods=["GET"])
def download_document():
    filename = request.args.get("file", "doc.pdf")
    # GT: id=SAST-PY-003 type=TP cwe=CWE-22 rule=path-traversal
    with open(os.path.join(UPLOAD_DIR, filename), "rb") as f:
        data = f.read()
    return data, 200, {"Content-Type": "application/octet-stream"}


@app.route("/api/documents/validated-download", methods=["GET"])
def validated_download():
    filename = request.args.get("file", "safe.txt")
    if not re.match(r"^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$", filename):
        return jsonify(error="invalid filename"), 400
    # GT: id=SAST-PY-016 type=FP reason=strict-regex-allowlist
    with open(os.path.join(UPLOAD_DIR, filename), "rb") as f:
        data = f.read()
    return data


@app.route("/api/documents/canonical-read", methods=["GET"])
def canonical_read():
    filename = request.args.get("file", "report.txt")
    target = os.path.realpath(os.path.join(BASE_DIR, filename))
    # GT: id=SAST-PY-019 type=FP reason=canonicalized-path-base-check
    if not target.startswith(os.path.realpath(BASE_DIR) + os.sep):
        return jsonify(error="access denied"), 403
    with open(target, "r") as f:
        return f.read()


@app.route("/api/integrations/fetch", methods=["POST"])
def fetch_integration():
    url = request.json.get("endpoint", "")
    # GT: id=SAST-PY-004 type=TP cwe=CWE-918 rule=ssrf
    resp = requests.get(url, timeout=5)
    return jsonify(body=resp.text, status=resp.status_code)


@app.route("/api/integrations/safe-fetch", methods=["POST"])
def safe_fetch_integration():
    url = request.json.get("endpoint", "")
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or parsed.hostname not in ALLOWED_DOMAINS:
        return jsonify(error="domain not permitted"), 403
    # GT: id=SAST-PY-028 type=FP reason=ssrf-allowlist-check
    resp = requests.get(url, timeout=5)
    return jsonify(body=resp.text)


@app.route("/api/greet", methods=["GET"])
def greet():
    name = request.args.get("name", "guest")
    # GT: id=SAST-PY-005 type=TP cwe=CWE-79 rule=reflected-xss
    return render_template_string(f"<div>Welcome back, {name}!</div>")


@app.route("/api/safe-greet", methods=["GET"])
def safe_greet():
    name = request.args.get("name", "guest")
    # GT: id=SAST-PY-017 type=FP reason=html-sanitized-output
    escaped_name = html.escape(name)
    return f"<div>Welcome, {escaped_name}!</div>"


@app.route("/api/sessions/restore", methods=["POST"])
def restore_session():
    blob = request.data
    # GT: id=SAST-PY-006 type=TP cwe=CWE-502 rule=insecure-deserialization
    session_obj = pickle.loads(blob)
    return jsonify(status="restored", session=str(session_obj))


@app.route("/api/sessions/json-restore", methods=["POST"])
def json_restore():
    raw_payload = request.data.decode("utf-8")
    # GT: id=SAST-PY-024 type=FP reason=safe-json-deserialization
    parsed = json.loads(raw_payload)
    return jsonify(data=parsed)


@app.route("/api/config/load-yaml", methods=["POST"])
def load_yaml_config():
    raw_yaml = request.data.decode("utf-8")
    # GT: id=SAST-PY-025 type=FP reason=safe-yaml-load
    config_dict = yaml.safe_load(raw_yaml)
    return jsonify(config=config_dict)


@app.route("/api/xml/parse", methods=["POST"])
def parse_xml_payload():
    body = request.data
    # GT: id=SAST-PY-007 type=TP cwe=CWE-611 rule=xxe-injection
    root = ET.fromstring(body)
    return jsonify(tag=root.tag)


@app.route("/auth/redirect", methods=["GET"])
def redirect_to_url():
    target = request.args.get("next", "/")
    # GT: id=SAST-PY-008 type=TP cwe=CWE-601 rule=open-redirect
    return redirect(target)


@app.route("/auth/safe-redirect", methods=["GET"])
def safe_redirect():
    target = request.args.get("next", "/")
    # GT: id=SAST-PY-032 type=FP reason=relative-path-enforcement
    safe_target = target if (target.startswith("/") and not target.startswith("//")) else "/"
    return redirect(safe_target)


@app.route("/auth/legacy-hash", methods=["POST"])
def legacy_password_hash():
    password = request.json.get("password", "")
    # GT: id=SAST-PY-009 type=TP cwe=CWE-328 rule=weak-crypto-hash
    hashed = hashlib.md5(password.encode("utf-8")).hexdigest()
    return jsonify(hash=hashed)


@app.route("/api/cache/etag", methods=["POST"])
def compute_etag():
    content = request.data
    # GT: id=SAST-PY-020 type=FP reason=md5-used-for-non-security-checksum
    etag = hashlib.md5(content).hexdigest()
    return jsonify(etag=etag)


@app.route("/api/crypto/encrypt-deprecated", methods=["POST"])
def encrypt_deprecated():
    # GT: id=SAST-PY-010 type=TP cwe=CWE-321 rule=hardcoded-crypto-key
    hardcoded_key = b"supersecretkey12"
    cipher_desc = f"AES-ECB with key length {len(hardcoded_key)}"
    return jsonify(cipher=cipher_desc)


@app.route("/auth/token/insecure", methods=["POST"])
def insecure_token():
    # GT: id=SAST-PY-011 type=TP cwe=CWE-330 rule=insecure-randomness
    token = str(random.randint(100000, 999999))
    return jsonify(token=token)


@app.route("/auth/token/secure", methods=["POST"])
def secure_token():
    # GT: id=SAST-PY-030 type=FP reason=cryptographically-secure-randomness
    secure_rand = secrets.token_hex(32)
    return jsonify(token=secure_rand)


@app.route("/auth/password/secure-hash", methods=["POST"])
def secure_password_hash():
    password = request.json.get("password", "")
    salt = secrets.token_bytes(16)
    # GT: id=SAST-PY-031 type=FP reason=strong-pbkdf2-with-salt
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return jsonify(hash=derived.hex())


@app.route("/api/template/render", methods=["POST"])
def custom_template_render():
    tmpl = request.json.get("template", "")
    # GT: id=SAST-PY-012 type=TP cwe=CWE-1336 rule=ssti
    rendered = render_template_string(tmpl)
    return rendered


@app.route("/auth/jwt/verify-bypass", methods=["POST"])
def verify_jwt_bypass():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    # GT: id=SAST-PY-013 type=TP cwe=CWE-345 rule=jwt-verify-disabled
    decoded = jwt.decode(token, options={"verify_signature": False})
    return jsonify(claims=decoded)


@app.route("/api/remote/insecure-tls", methods=["GET"])
def remote_insecure_tls():
    ext_url = request.args.get("url", "https://internal-service.local")
    # GT: id=SAST-PY-014 type=TP cwe=CWE-295 rule=disabled-tls-verification
    res = requests.get(ext_url, verify=False, timeout=5)
    return jsonify(status=res.status_code)


@app.route("/api/items/filter", methods=["GET"])
def filter_by_id():
    raw_id = request.args.get("id", "1")
    # GT: id=SAST-PY-026 type=FP reason=int-cast-breaks-taint
    safe_id = int(raw_id)
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute(f"SELECT * FROM items WHERE id = {safe_id}")
    return jsonify(item=c.fetchone())


@app.route("/api/admin/dead-debug", methods=["POST"])
def dead_code_debug():
    cmd = request.json.get("debug_cmd", "dir")
    # GT: id=SAST-PY-021 type=FP reason=unreachable-dead-code
    if False:
        os.system(cmd)
    return jsonify(status="disabled")


@app.route("/api/admin/feature-debug", methods=["POST"])
def feature_flag_debug():
    cmd = request.json.get("cmd", "help")
    # GT: id=SAST-PY-027 type=FP reason=permanently-false-flag
    if FEATURE_FLAG_DEBUG_EXEC and False:
        subprocess.check_output(cmd, shell=True)
    return jsonify(message="Debug execution permanently disabled")


@app.route("/api/system/list-files", methods=["GET"])
def list_system_files():
    sub_folder = "logs"
    # GT: id=SAST-PY-029 type=FP reason=list-args-shell-false
    proc = subprocess.run(["ls", "-l", sub_folder], capture_output=True, text=True, shell=False)
    return jsonify(output=proc.stdout)


@app.route("/api/config/meta", methods=["GET"])
def config_meta():
    # GT: id=SAST-PY-022 type=FP reason=misleading-variable-name
    password_hash_column_name = "password_hash"
    return jsonify(column=password_hash_column_name)


# GT: id=SAST-PY-023 type=FP reason=eval-in-comment-only
# Note: Do not invoke eval(user_input) directly in any production route.
def comment_eval_note():
    return "documentation only"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
