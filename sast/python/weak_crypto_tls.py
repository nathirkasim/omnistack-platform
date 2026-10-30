import hashlib
import requests

def hash_password_insecure(password: str) -> str:
    # VULNERABLE: MD5 is broken and insecure for password hashing (CWE-327, CWE-328)
    return hashlib.md5(password.encode("utf-8")).hexdigest()

def fetch_internal_auth(auth_server_url: str):
    # VULNERABLE: Certificate verification explicitly disabled (CWE-295)
    return requests.get(auth_server_url, verify=False, timeout=5)
