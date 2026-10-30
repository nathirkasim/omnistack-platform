from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

@app.route("/api/webhook/test", methods=["POST"])
def trigger_webhook():
    payload = request.get_json() or {}
    webhook_url = payload.get("url")
    # VULNERABLE: Untrusted user-supplied URL fetched directly without validation (CWE-918)
    resp = requests.get(webhook_url, timeout=5)
    return jsonify({"status_code": resp.status_code, "body": resp.text[:200]})
