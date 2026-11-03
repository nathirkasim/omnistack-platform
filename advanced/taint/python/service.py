"""
Business Logic and Service Orchestration Layer for Deep Taint Analysis
"""

import subprocess
import requests
import os
from .repository import OrderRepository
from .sanitizer import (
    noop_sanitize,
    wrong_context_sanitize,
    bypassable_blocklist,
    strict_allowlist_validator,
    is_safe_canonical_path
)

class StatefulTaskService:
    def __init__(self):
        self.pending_cmd = ""
        self.sanitized_field = ""

    def stage_command(self, cmd: str):
        self.pending_cmd = cmd

    def stage_safe_field(self, field: str):
        self.sanitized_field = field if strict_allowlist_validator(field) else "default"

    def dispatch_pending(self):
        # GT: id=TAINT-PY-002 type=TP cwe=CWE-78 rule=class-field-taint-exec
        return subprocess.check_output(self.pending_cmd, shell=True, text=True)

    def dispatch_safe(self):
        # GT: id=TAINT-PY-012 type=FP reason=sanitized-class-field-exec
        return subprocess.check_output(["echo", self.sanitized_field], text=True)


class HigherOrderService:
    @staticmethod
    def execute_with_callback(payload: str, callback):
        return callback(payload)

    @staticmethod
    def run_command_callback(cmd: str):
        # GT: id=TAINT-PY-003 type=TP cwe=CWE-78 rule=closure-callback-command-injection
        return subprocess.run(f"echo processing {cmd}", shell=True, capture_output=True, text=True).stdout

    @staticmethod
    def run_safe_callback(val: str):
        if not strict_allowlist_validator(val):
            return "rejected"
        # GT: id=TAINT-PY-013 type=FP reason=closure-allowlist-validated
        return subprocess.run(["echo", val], capture_output=True, text=True).stdout


class DeepTaintService:
    def __init__(self):
        self.repo = OrderRepository()

    def process_order_filter(self, raw_filter: str):
        return self._transform_step_1(raw_filter)

    def _transform_step_1(self, f: str):
        return self._transform_step_2(f)

    def _transform_step_2(self, f: str):
        return self.repo.execute_raw_sql(f)

    def process_safe_order(self, raw_id: str):
        return self.repo.execute_parameterized(raw_id)

    def fetch_with_noop_sanitizer(self, raw_url: str):
        cleaned_url = noop_sanitize(raw_url)
        # GT: id=TAINT-PY-006 type=TP cwe=CWE-918 rule=noop-sanitizer-ssrf
        return requests.get(cleaned_url, timeout=3).text

    def fetch_with_allowlist(self, raw_url: str, allowed_host: str):
        if not raw_url.startswith(f"https://{allowed_host}/"):
            return "forbidden"
        # GT: id=TAINT-PY-017 type=FP reason=strict-url-prefix-allowlist
        return requests.get(raw_url, timeout=3).text

    def query_with_wrong_sanitizer(self, user_str: str):
        html_escaped = wrong_context_sanitize(user_str)
        # GT: id=TAINT-PY-007 type=TP cwe=CWE-89 rule=wrong-context-sanitizer-sqli
        return self.repo.execute_raw_sql(html_escaped)

    def read_with_bypassable_filter(self, base_dir: str, filename: str):
        filtered_name = bypassable_blocklist(filename)
        # GT: id=TAINT-PY-009 type=TP cwe=CWE-22 rule=bypassable-blocklist-traversal
        with open(os.path.join(base_dir, filtered_name), "r") as f:
            return f.read()

    def read_with_canonical_check(self, base_dir: str, filename: str):
        if not is_safe_canonical_path(base_dir, filename):
            return "forbidden"
        # GT: id=TAINT-PY-018 type=FP reason=canonical-validator-path-traversal
        with open(os.path.join(base_dir, filename), "r") as f:
            return f.read()

