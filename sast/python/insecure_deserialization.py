from flask import Flask, request, jsonify
import base64
import pickle

app = Flask(__name__)

@app.route("/api/session/restore", methods=["POST"])
def restore_session():
    data = request.get_json() or {}
    raw_cookie = data.get("session_data", "")
    serialized_bytes = base64.b64decode(raw_cookie)
    # VULNERABLE: Untrusted data passed to pickle.loads executes arbitrary code (CWE-502)
    user_session = pickle.loads(serialized_bytes)
    return jsonify({"user": str(user_session)})
