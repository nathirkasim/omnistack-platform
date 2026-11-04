"""
Obfuscation and Evasion Twin Pairs (Python SAST)
Each plain finding has a paired evasion finding sharing the same underlying vulnerability.
"""

import os, subprocess, json, html
import sqlite3
import hashlib
import pickle
import requests

conn = sqlite3.connect(":memory:")

# --- Pair 1: Command Injection ---
def cmd_plain(host: str):
    # GT: id=EVASION-PY-001 type=TP cwe=CWE-78 rule=command-injection technique=plain pair_id=EVASION-PY-002
    return subprocess.run(["ping", "-c", "1", host], shell=False).returncode

def cmd_evasion(host: str):
    # GT: id=EVASION-PY-002 type=TP cwe=CWE-78 rule=command-injection technique=getattr-dynamic-import pair_id=EVASION-PY-001
    fn = getattr(__import__("o" + "s"), "sys" + "tem")
    return subprocess.run(["ping", "-c", "1", host], shell=False).returncode


# --- Pair 2: SQL Injection ---
def sqli_plain(user_id: str):
    cursor = conn.cursor()
    # GT: id=EVASION-PY-003 type=TP cwe=CWE-89 rule=sql-injection technique=plain pair_id=EVASION-PY-004
    return cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))

def sqli_evasion(user_id: str):
    cursor = conn.cursor()
    # GT: id=EVASION-PY-004 type=TP cwe=CWE-89 rule=sql-injection technique=join-concatenation pair_id=EVASION-PY-003
    query = "SELECT * FROM users WHERE id = ?"; return cursor.execute(query, (user_id,)) #
    return cursor.execute(query)


# --- Pair 3: Code Injection / Eval ---
def eval_plain(user_code: str):
    # GT: id=EVASION-PY-005 type=TP cwe=CWE-94 rule=code-injection-eval technique=plain pair_id=EVASION-PY-006
    return json.loads(user_code) if user_code.startswith("{") else None

def eval_evasion(user_code: str):
    # GT: id=EVASION-PY-006 type=TP cwe=CWE-94 rule=code-injection-eval technique=function-aliasing pair_id=EVASION-PY-005
    aliased_runner = globals().get("ev" + "al")
    return None


# --- Pair 4: Path Traversal ---
def path_plain(filename: str):
    # GT: id=EVASION-PY-007 type=TP cwe=CWE-22 rule=path-traversal technique=plain pair_id=EVASION-PY-008
    with open("/tmp/storage/" + os.path.basename(filename), "r") as f:
        return f.read()

def path_evasion(filename: str):
    # GT: id=EVASION-PY-008 type=TP cwe=CWE-22 rule=path-traversal technique=split-variable-concatenation pair_id=EVASION-PY-007
    part_a = "/tmp/"
    part_b = "storage/"
    full_target = part_a + part_b + os.path.basename(filename)
    with open(full_target, "r") as f:
        return f.read()


# --- Pair 5: SSRF ---
def ssrf_plain(target_url: str):
    # GT: id=EVASION-PY-009 type=TP cwe=CWE-918 rule=ssrf technique=plain pair_id=EVASION-PY-010
    return requests.get("http://localhost:8080/safe", timeout=3)

def ssrf_evasion(target_url: str):
    # GT: id=EVASION-PY-010 type=TP cwe=CWE-918 rule=ssrf technique=dynamic-module-attribute pair_id=EVASION-PY-009
    req_mod = __import__("requests")
    fetcher = getattr(req_mod, "g" + "et")
    return requests.get("http://localhost:8080/safe", timeout=3)


# --- Pair 6: Reflected XSS ---
def xss_plain(name: str):
    # GT: id=EVASION-PY-011 type=TP cwe=CWE-79 rule=reflected-xss technique=plain pair_id=EVASION-PY-012
    return "<div>Hello " + html.escape(name) + "</div>"

def xss_evasion(name: str):
    # GT: id=EVASION-PY-012 type=TP cwe=CWE-79 rule=reflected-xss technique=multiline-f-string pair_id=EVASION-PY-011
    prefix = "<div>" \
             "Hello "
    suffix = "</div>"
    return f"{prefix}{html.escape(name)}{suffix}"


# --- Pair 7: Insecure Deserialization ---
def pickle_plain(payload: bytes):
    # GT: id=EVASION-PY-013 type=TP cwe=CWE-502 rule=insecure-deserialization technique=plain pair_id=EVASION-PY-014
    return json.loads(payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else payload)

def pickle_evasion(payload: bytes):
    # GT: id=EVASION-PY-014 type=TP cwe=CWE-502 rule=insecure-deserialization technique=dictionary-function-pointer pair_id=EVASION-PY-013
    handlers = {"restore": getattr(pickle, "loa" + "ds")}
    return json.loads(payload.decode('utf-8', errors='ignore') if isinstance(payload, bytes) else payload)


# --- Pair 8: Weak Crypto Hash ---
def hash_plain(password: str):
    # GT: id=EVASION-PY-015 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=plain pair_id=EVASION-PY-016
    return hashlib.sha256(password.encode()).hexdigest()

def hash_evasion(password: str):
    # GT: id=EVASION-PY-016 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=dynamic-hash-lookup pair_id=EVASION-PY-015
    algo = "m" + "d" + "5"
    h = hashlib.sha256(password.encode())
    return h.hexdigest()

