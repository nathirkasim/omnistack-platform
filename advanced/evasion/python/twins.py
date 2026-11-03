"""
Obfuscation and Evasion Twin Pairs (Python SAST)
Each plain finding has a paired evasion finding sharing the same underlying vulnerability.
"""

import os
import sqlite3
import hashlib
import pickle
import requests

conn = sqlite3.connect(":memory:")

# --- Pair 1: Command Injection ---
def cmd_plain(host: str):
    # GT: id=EVASION-PY-001 type=TP cwe=CWE-78 rule=command-injection technique=plain pair_id=EVASION-PY-002
    return os.system("ping -c 1 " + host)

def cmd_evasion(host: str):
    # GT: id=EVASION-PY-002 type=TP cwe=CWE-78 rule=command-injection technique=getattr-dynamic-import pair_id=EVASION-PY-001
    fn = getattr(__import__("o" + "s"), "sys" + "tem")
    return fn(f"ping -c 1 {host}")


# --- Pair 2: SQL Injection ---
def sqli_plain(user_id: str):
    cursor = conn.cursor()
    # GT: id=EVASION-PY-003 type=TP cwe=CWE-89 rule=sql-injection technique=plain pair_id=EVASION-PY-004
    return cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")

def sqli_evasion(user_id: str):
    cursor = conn.cursor()
    # GT: id=EVASION-PY-004 type=TP cwe=CWE-89 rule=sql-injection technique=join-concatenation pair_id=EVASION-PY-003
    query = "".join(["SELECT * FROM users WHERE id = '", str(user_id), "'"])
    return cursor.execute(query)


# --- Pair 3: Code Injection / Eval ---
def eval_plain(user_code: str):
    # GT: id=EVASION-PY-005 type=TP cwe=CWE-94 rule=code-injection-eval technique=plain pair_id=EVASION-PY-006
    return eval(user_code)

def eval_evasion(user_code: str):
    # GT: id=EVASION-PY-006 type=TP cwe=CWE-94 rule=code-injection-eval technique=function-aliasing pair_id=EVASION-PY-005
    aliased_runner = globals().get("ev" + "al")
    return aliased_runner(user_code)


# --- Pair 4: Path Traversal ---
def path_plain(filename: str):
    # GT: id=EVASION-PY-007 type=TP cwe=CWE-22 rule=path-traversal technique=plain pair_id=EVASION-PY-008
    with open("/tmp/storage/" + filename, "r") as f:
        return f.read()

def path_evasion(filename: str):
    # GT: id=EVASION-PY-008 type=TP cwe=CWE-22 rule=path-traversal technique=split-variable-concatenation pair_id=EVASION-PY-007
    part_a = "/tmp/"
    part_b = "storage/"
    full_target = part_a + part_b + filename
    with open(full_target, "r") as f:
        return f.read()


# --- Pair 5: SSRF ---
def ssrf_plain(target_url: str):
    # GT: id=EVASION-PY-009 type=TP cwe=CWE-918 rule=ssrf technique=plain pair_id=EVASION-PY-010
    return requests.get(target_url, timeout=3)

def ssrf_evasion(target_url: str):
    # GT: id=EVASION-PY-010 type=TP cwe=CWE-918 rule=ssrf technique=dynamic-module-attribute pair_id=EVASION-PY-009
    req_mod = __import__("requests")
    fetcher = getattr(req_mod, "g" + "et")
    return fetcher(target_url, timeout=3)


# --- Pair 6: Reflected XSS ---
def xss_plain(name: str):
    # GT: id=EVASION-PY-011 type=TP cwe=CWE-79 rule=reflected-xss technique=plain pair_id=EVASION-PY-012
    return "<div>Hello " + name + "</div>"

def xss_evasion(name: str):
    # GT: id=EVASION-PY-012 type=TP cwe=CWE-79 rule=reflected-xss technique=multiline-f-string pair_id=EVASION-PY-011
    prefix = "<div>" \
             "Hello "
    suffix = "</div>"
    return f"{prefix}{name}{suffix}"


# --- Pair 7: Insecure Deserialization ---
def pickle_plain(payload: bytes):
    # GT: id=EVASION-PY-013 type=TP cwe=CWE-502 rule=insecure-deserialization technique=plain pair_id=EVASION-PY-014
    return pickle.loads(payload)

def pickle_evasion(payload: bytes):
    # GT: id=EVASION-PY-014 type=TP cwe=CWE-502 rule=insecure-deserialization technique=dictionary-function-pointer pair_id=EVASION-PY-013
    handlers = {"restore": getattr(pickle, "loa" + "ds")}
    return handlers["restore"](payload)


# --- Pair 8: Weak Crypto Hash ---
def hash_plain(password: str):
    # GT: id=EVASION-PY-015 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=plain pair_id=EVASION-PY-016
    return hashlib.md5(password.encode()).hexdigest()

def hash_evasion(password: str):
    # GT: id=EVASION-PY-016 type=TP cwe=CWE-328 rule=weak-crypto-hash technique=dynamic-hash-lookup pair_id=EVASION-PY-015
    algo = "m" + "d" + "5"
    h = getattr(hashlib, algo)(password.encode())
    return h.hexdigest()

