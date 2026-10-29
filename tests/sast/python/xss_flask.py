"""
SAST Test Fixture: Cross-Site Scripting (XSS) in Python / Flask
Covers paired True Positives and False Positives.
"""
from flask import Flask, request, render_template_string, render_template, Response, jsonify
from markupsafe import Markup, escape
import bleach

app = Flask(__name__)

# ==============================================================================
# TP-SAST-003: Reflected XSS via unescaped template string rendering
# CWE-79 | High Severity
# ==============================================================================
@app.route("/vulnerable/greet")
def greet_vulnerable():
    name = request.args.get("name", "")
    # Vulnerable: Concatenating untrusted user input directly into HTML template
    template = f"<h1>Hello, {name}!</h1>"
    return render_template_string(template)


# ==============================================================================
# FP-SAST-005: Safe XSS Defense via Jinja2 auto-escaped template rendering
# Expected: Safe / No detection
# ==============================================================================
@app.route("/safe/greet")
def greet_safe():
    name = request.args.get("name", "")
    # Safe: Passing user input as context variable to auto-escaped template
    return render_template_string("<h1>Hello, {{ name }}!</h1>", name=name)


# ==============================================================================
# TP-SAST-004: Stored / Reflected XSS via explicit unescaped Markup() wrapper
# CWE-79 | High Severity
# ==============================================================================
@app.route("/vulnerable/markup")
def markup_vulnerable():
    bio = request.args.get("bio", "")
    # Vulnerable: Explicitly marking untrusted input as safe HTML
    safe_bio = Markup(bio)
    return render_template_string("<div>User Bio: {{ bio }}</div>", bio=safe_bio)


# ==============================================================================
# FP-SAST-006: Explicit sanitization using Bleach before Markup() wrapper
# Expected: Safe / Sanitized before rendering
# ==============================================================================
@app.route("/safe/sanitized-markup")
def markup_safe():
    bio = request.args.get("bio", "")
    # Safe: Sanitizing input with strict tag allowlist before wrapping
    cleaned_bio = bleach.clean(bio, tags=["b", "i", "u", "em", "strong"], strip=True)
    safe_bio = Markup(cleaned_bio)
    return render_template_string("<div>User Bio: {{ bio }}</div>", bio=safe_bio)


# ==============================================================================
# FP-SAST-007: Safe JSON / Text API output containing HTML-like strings
# Expected: Safe (Content-Type: application/json, browser will not interpret as HTML)
# ==============================================================================
@app.route("/safe/api-response")
def api_response_safe():
    # User input might contain "<script>alert(1)</script>" but it is JSON encoded
    raw_data = request.args.get("raw", "")
    return jsonify({"status": "success", "echo": raw_data})
