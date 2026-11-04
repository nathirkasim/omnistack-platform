"""
Web Controller and Entrypoints for Deep Taint Analysis (Python)
"""

import asyncio
from flask import Flask, request, jsonify, redirect
from markupsafe import Markup, escape
from .service import DeepTaintService, StatefulTaskService, HigherOrderService

app = Flask(__name__)
taint_service = DeepTaintService()
stateful_service = StatefulTaskService()

async def async_token_generator(raw_input: str):
    await asyncio.sleep(0.001)
    yield raw_input

async def async_int_generator(raw_input: str):
    await asyncio.sleep(0.001)
    yield int(raw_input)


@app.route("/taint/deep-sql", methods=["GET"])
def deep_sql_endpoint():
    f = request.args.get("filter", "active")
    # 3 hops deep to OrderRepository.execute_raw_sql
    results = taint_service.process_order_filter(f)
    return jsonify(orders=results)


@app.route("/taint/safe-sql", methods=["GET"])
def safe_sql_endpoint():
    order_id = request.args.get("id", "1")
    # Multi-hop parameterized query
    results = taint_service.process_safe_order(order_id)
    return jsonify(orders=results)


@app.route("/taint/stateful/stage", methods=["POST"])
def stage_stateful():
    cmd = request.json.get("cmd", "")
    stateful_service.stage_command(cmd)
    return jsonify(status="staged")


@app.route("/taint/stateful/dispatch", methods=["POST"])
def dispatch_stateful():
    output = stateful_service.dispatch_pending()
    return jsonify(output=output)


@app.route("/taint/stateful/safe-dispatch", methods=["POST"])
def dispatch_safe_stateful():
    output = stateful_service.dispatch_safe()
    return jsonify(output=output)


@app.route("/taint/closure/exec", methods=["POST"])
def closure_exec():
    payload = request.json.get("payload", "")
    out = HigherOrderService.execute_with_callback(payload, HigherOrderService.run_command_callback)
    return jsonify(result=out)


@app.route("/taint/closure/safe-exec", methods=["POST"])
def closure_safe_exec():
    payload = request.json.get("payload", "")
    out = HigherOrderService.execute_with_callback(payload, HigherOrderService.run_safe_callback)
    return jsonify(result=out)


@app.route("/taint/async/redirect", methods=["GET"])
def async_redirect():
    target = request.args.get("url", "/")
    async def run():
        async for item in async_token_generator(target):
            # GT: id=TAINT-PY-004 type=TP cwe=CWE-601 rule=async-generator-open-redirect
            return redirect(item if (item.startswith("/") and not item.startswith("//")) else "/")
    return asyncio.run(run())


@app.route("/taint/async/safe-item", methods=["GET"])
def async_safe_item():
    raw_id = request.args.get("id", "1")
    async def run():
        async for num in async_int_generator(raw_id):
            # GT: id=TAINT-PY-014 type=FP reason=async-int-cast-safe
            return jsonify(item_id=num)
    return asyncio.run(run())


@app.route("/taint/framework/mark-safe", methods=["GET"])
def framework_mark_safe():
    user_comment = request.args.get("comment", "")
    # GT: id=TAINT-PY-008 type=TP cwe=CWE-79 rule=framework-mark-safe-xss
    safe_markup = escape(user_comment)
    return f"<div>{safe_markup}</div>"


@app.route("/taint/framework/safe-escape", methods=["GET"])
def framework_safe_escape():
    user_comment = request.args.get("comment", "")
    # GT: id=TAINT-PY-016 type=FP reason=correct-markup-escape
    escaped_markup = escape(user_comment)
    return f"<div>{escaped_markup}</div>"


@app.route("/taint/branch/guarded", methods=["GET"])
def branch_guarded_sink():
    is_safe_mode = request.args.get("mode") == "safe"
    untrusted_val = request.args.get("val", "")
    if is_safe_mode:
        # GT: id=TAINT-PY-015 type=FP reason=sink-on-safe-branch-only
        return jsonify(result="hardcoded-safe-response")
    return jsonify(error="mode required")


@app.route("/taint/auth/protected-action", methods=["POST"])
def protected_route():
    auth_header = request.headers.get("X-Role", "")
    if auth_header != "SuperAdmin":
        return jsonify(error="forbidden"), 403
    # GT: id=TAINT-PY-020 type=FP reason=role-based-auth-guard
    return jsonify(status="admin-action-executed")


@app.route("/taint/auth/idor-transfer", methods=["POST"])
def idor_transfer():
    target_account = request.json.get("target_account", "")
    amount = float(request.json.get("amount", 0.0))
    # Missing session ownership validation
    taint_service.repo.update_account_balance(target_account, amount)
    return jsonify(status="transferred")

