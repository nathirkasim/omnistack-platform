"""
SAST Test Fixture: Cryptography and Authentication (Python)
Covers paired True Positives and False Positives.
"""
import hashlib
import random
import secrets
import bcrypt
from flask import Flask, request, jsonify

app = Flask(__name__)

# ==============================================================================
# TP-SAST-011: Weak Cryptographic Hash (MD5) used for Password Storage
# CWE-328 / CWE-327 | High Severity
# ==============================================================================
def hash_password_insecure(password: str) -> str:
    # Vulnerable: MD5 is broken and unsuitable for password hashing or cryptographic integrity
    return hashlib.md5(password.encode("utf-8")).hexdigest()


# ==============================================================================
# FP-SAST-017: MD5 used strictly for Non-Security Cache / ETag Key
# Expected: Safe / False Positive if flagged as weak password hashing
# ==============================================================================
def compute_static_asset_cache_key(file_content: bytes) -> str:
    # Safe: MD5 used purely as a fast checksum for static cache busting
    return "asset-" + hashlib.md5(file_content).hexdigest()


# ==============================================================================
# TP-SAST-012: Insecure Random Number Generator for Security Token
# CWE-338 | High Severity
# ==============================================================================
def generate_password_reset_token_insecure() -> str:
    # Vulnerable: random.random() is pseudo-random (Mersenne Twister) and predictable
    return str(random.getrandbits(128))


# ==============================================================================
# FP-SAST-018: Cryptographically Secure Random Token Generation
# Expected: Safe (uses CSPRNG secrets module)
# ==============================================================================
def generate_password_reset_token_safe() -> str:
    # Safe: secrets.token_hex uses os.urandom (cryptographically strong PRNG)
    return secrets.token_hex(32)


# ==============================================================================
# TP-SAST-013: Fast Hash (SHA-256 without salt/work-factor) for Password Hashing
# CWE-916 | Medium Severity
# ==============================================================================
def hash_password_fast_sha256(password: str) -> str:
    # Inadequate: Plain unsalted SHA-256 vulnerable to GPU brute-forcing and rainbow tables
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


# ==============================================================================
# FP-SAST-019: Adaptive Password Hashing via bcrypt
# Expected: Safe / Industry Standard
# ==============================================================================
def hash_password_secure_bcrypt(password: str) -> str:
    # Safe: Uses bcrypt with salt and configurable work factor
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


# ==============================================================================
# TP-SAST-014: Missing Authorization Check on Sensitive Administrative Endpoint
# CWE-306 | High Severity
# ==============================================================================
@app.route("/admin/delete-all-users", methods=["POST"])
def admin_delete_all_users_vulnerable():
    # Vulnerable: Sensitive mutation endpoint accessible without authentication/role check
    return jsonify({"status": "all_users_purged"})


# ==============================================================================
# FP-SAST-020: Intentional Public Health Check / Metrics Endpoint
# Expected: Safe (Public by design)
# ==============================================================================
@app.route("/healthz", methods=["GET"])
def health_check_public_safe():
    # Safe: Liveness probe intended to be publicly reachable by orchestration health check
    return jsonify({"status": "UP", "version": "1.0.0"})
