from flask import Flask, request
from jinja2 import Environment

app = Flask(__name__)

@app.route("/api/greet", methods=["GET"])
def greet():
    name = request.args.get("name", "Guest")
    # VULNERABLE: Untrusted user input rendered directly as a template string (CWE-1336)
    template_str = f"Hello, {name}! Welcome to our platform."
    env = Environment()
    template = env.from_string(template_str)
    return template.render()
