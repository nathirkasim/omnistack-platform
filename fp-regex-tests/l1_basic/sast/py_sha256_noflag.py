import hashlib
def hash_payload(data):
    return hashlib.sha256(data.encode()).hexdigest()
