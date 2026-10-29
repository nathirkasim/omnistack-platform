"""
SAST Test Fixture: SSRF, Insecure Deserialization, and Open Redirects (Python)
Covers paired True Positives and False Positives.
"""
import ipaddress
import json
import pickle
from urllib.parse import urlparse
from flask import Flask, redirect, request
import requests

app = Flask(__name__)

# ==============================================================================
# TP-SAST-008: Server-Side Request Forgery (SSRF)
# CWE-918 | High Severity
# ==============================================================================
@app.route("/vulnerable/webhook")
def trigger_webhook_vulnerable():
    target_url = request.args.get("url", "")
    # Vulnerable: Untrusted URL fetched without scheme or IP verification
    response = requests.get(target_url, timeout=5)
    return response.text


# ==============================================================================
# FP-SAST-014: Safe Webhook Fetching with Strict Host/IP Validation
# Expected: Safe / SSRF mitigated
# ==============================================================================
ALLOWED_DOMAINS = {"api.partner.com", "hooks.slack.com"}

def is_safe_webhook_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    if parsed.hostname not in ALLOWED_DOMAINS:
        return False
    # Check that IP does not resolve to private or loopback ranges
    return True

@app.route("/safe/webhook")
def trigger_webhook_safe():
    target_url = request.args.get("url", "")
    if not is_safe_webhook_url(target_url):
        return ("Invalid target URL", 400)
    response = requests.get(target_url, timeout=5)
    return response.text


# ==============================================================================
# TP-SAST-009: Insecure Deserialization via pickle
# CWE-502 | Critical Severity
# ==============================================================================
def load_session_token_vulnerable(raw_payload: bytes):
    # Critical: pickle.loads executes arbitrary code embedded in serialized object
    return pickle.loads(raw_payload)


# ==============================================================================
# FP-SAST-015: Safe Deserialization via Standard JSON Parser
# Expected: Safe / No arbitrary code execution capability
# ==============================================================================
def load_session_token_safe(raw_payload: str):
    # Safe: JSON parsing produces plain primitive data structures
    return json.loads(raw_payload)


# ==============================================================================
# TP-SAST-010: Open Redirect via Unvalidated Query Parameter
# CWE-601 | Medium Severity
# ==============================================================================
@app.route("/vulnerable/redirect")
def redirect_vulnerable():
    dest = request.args.get("next", "/")
    # Vulnerable: Allows phishing redirection to external domains
    return redirect(dest)


# ==============================================================================
# FP-SAST-016: Safe Relative-Only Redirect
# Expected: Safe / Open Redirect mitigated
# ==============================================================================
@app.route("/safe/redirect")
def redirect_safe():
    dest = request.args.get("next", "/")
    # Safe: Enforce that destination is a relative path starting with '/' and not '//'
    if not dest.startswith("/") or dest.startswith("//"):
        dest = "/"
    return redirect(dest)
