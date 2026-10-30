from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)

@app.route("/api/user/search", methods=["GET"])
def search_user():
    username = request.args.get("username", "")
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # VULNERABLE: Direct string interpolation into SQL query (CWE-89)
    query = f"SELECT id, username, email FROM users WHERE username = '{username}'"
    cursor.execute(query)
    results = cursor.fetchall()
    conn.close()
    return jsonify(results)
