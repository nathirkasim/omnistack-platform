from flask import Flask, request, send_file, abort
import os

app = Flask(__name__)
STORAGE_DIR = "/var/app/data/reports"

@app.route("/api/reports/download", methods=["GET"])
def download_report():
    filename = request.args.get("file", "")
    # VULNERABLE: Direct path concatenation allowing ../ traversal outside STORAGE_DIR (CWE-22)
    target_path = os.path.join(STORAGE_DIR, filename)
    if os.path.exists(target_path):
        return send_file(target_path)
    abort(404)
