"""
Secrets Detection Fixture: False Positives Matrix
Tests that harmless placeholders, documentation, and synthetic structures are NOT flagged.
"""
import os
import uuid

# ==============================================================================
# FP-SECRET-001: Obvious placeholders
# Expected: Ignore / No finding
# ==============================================================================
API_KEY_PLACEHOLDER = "YOUR_API_KEY_HERE"
DB_PASSWORD_PLACEHOLDER = "CHANGEME"
AUTH_TOKEN_PLACEHOLDER = "<INSERT_TOKEN_HERE>"
JWT_SECRET_PLACEHOLDER = "your-secret-key-goes-here"

# ==============================================================================
# FP-SECRET-002: Synthetic token with invalid / reserved AWS example format
# Expected: Ignore / Recognized as synthetic test marker
# ==============================================================================
AWS_RESERVED_DOC_ID = "AKIA00000000EXAMPLE0"

# ==============================================================================
# FP-SECRET-004: Redacted credentials
# Expected: Ignore / Recognized as masked string
# ==============================================================================
MASKED_GITHUB_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
MASKED_STRIPE_KEY = "sk_live_********************************"

# ==============================================================================
# FP-SECRET-006: Environment variable references
# Expected: Safe / No hardcoded secret
# ==============================================================================
AWS_SECRET = os.environ.get("AWS_SECRET_ACCESS_KEY", "")
STRIPE_API_KEY = os.getenv("STRIPE_SECRET_KEY", "")

# ==============================================================================
# FP-SECRET-007: Secret-like high entropy identifiers / hashes / UUIDs
# Expected: Safe / Non-secret identifier
# ==============================================================================
SAMPLE_UUID = "550e8400-e29b-41d4-a716-446655440000"
SHA256_CACHE_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
GIT_COMMIT_HASH = "48a631754a6f250e498776469fef490d1b054cea"
CSS_CLASS_HASH = "btn-primary-hash-8f4b2c1e"
