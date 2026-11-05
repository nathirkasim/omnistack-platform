import hashlib
def generate_cache_key(url):
    return hashlib.md5(url.encode(), usedforsecurity=False).hexdigest()
