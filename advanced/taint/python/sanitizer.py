"""
Sanitizer and Validator Utilities for Deep Taint Analysis
"""

import html
import re
import os

def noop_sanitize(val: str) -> str:
    """Trap: Appears to sanitize but returns identical untamed value."""
    return val

def wrong_context_sanitize(val: str) -> str:
    """Trap: HTML escapes input, which does not prevent SQL injection."""
    return html.escape(val)

def bypassable_blocklist(val: str) -> str:
    """Trap: Replaces '../' once, trivially bypassed by '....//'."""
    return val.replace("../", "")

def strict_allowlist_validator(val: str) -> bool:
    """Safe validator: Enforces alphanumeric format."""
    return bool(re.match(r"^[a-zA-Z0-9_\-]+$", val))

def is_safe_canonical_path(base_dir: str, target_filename: str) -> bool:
    """Safe validator: Validates canonical base directory prefix."""
    full_path = os.path.realpath(os.path.join(base_dir, target_filename))
    return full_path.startswith(os.path.realpath(base_dir) + os.sep)
