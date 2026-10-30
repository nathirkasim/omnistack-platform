from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route("/api/network/ping", methods=["POST"])
def ping_host():
    data = request.get_json() or {}
    target = data.get("host", "127.0.0.1")
    # VULNERABLE: User input concatenated into shell command with shell=True (CWE-78)
    cmd = f"ping -c 1 {target}"
    result = subprocess.check_output(cmd, shell=True, text=True)
    return jsonify({"output": result})
