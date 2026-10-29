"""
SAST Test Fixture: Command Injection (Python)
Covers paired True Positives and False Positives.
"""
import os
import re
import shlex
import subprocess

# ==============================================================================
# TP-SAST-005: Command Injection via os.system shell string
# CWE-78 | Critical Severity
# ==============================================================================
def ping_host_vulnerable(host_input: str):
    # Vulnerable: Untrusted input concatenated into shell command
    command = "ping -c 1 " + host_input
    return os.system(command)


# ==============================================================================
# FP-SAST-008: Safe Process Execution without Shell (argument list)
# Expected: Safe / No finding
# ==============================================================================
def ping_host_safe_argv(host_input: str):
    # Safe: Arguments passed as discrete array elements, shell=False
    # Shell meta-characters like ';', '&', '|' are treated as literal argument values
    result = subprocess.run(
        ["ping", "-c", "1", host_input],
        shell=False,
        capture_output=True,
        text=True,
        check=False
    )
    return result.returncode


# ==============================================================================
# TP-SAST-006: Ineffective Sanitization Command Injection
# CWE-78 | High Severity
# Strips semicolon but leaves pipe, ampersand, and backticks unhandled
# ==============================================================================
def run_diag_ineffective_sanitization(user_arg: str):
    # Ineffective: only removes semicolon, allowing '8.8.8.8 && id' or '`id`'
    sanitized = user_arg.replace(";", "")
    cmd = f"nslookup {sanitized}"
    return subprocess.run(cmd, shell=True, capture_output=True)


# ==============================================================================
# FP-SAST-009: Strict Regex Validation before Shell Invocation
# Expected: Safe / Conditional (validates that input strictly conforms to alphanumeric domain)
# ==============================================================================
def run_diag_strictly_validated(user_arg: str):
    # Safe: Strict whitelist regex guarantees no shell metacharacters can pass
    if not re.match(r"^[a-zA-Z0-9.-]+$", user_arg):
        raise ValueError("Invalid domain format")
    cmd = f"nslookup {user_arg}"
    return subprocess.run(cmd, shell=True, capture_output=True)


# ==============================================================================
# FP-SAST-010: Hardcoded / Static Command in Subprocess (Safe appearance)
# Resembles shell call, but zero user taint.
# ==============================================================================
def clean_temporary_cache_safe():
    # Safe: Purely static string, no external input
    return subprocess.run("rm -rf /tmp/my_app_cache_*", shell=True, check=False)
