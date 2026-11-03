"""
Cloud and Service Credentials Configuration (Synthetic Test Fixtures)
All credentials and tokens in this file are strictly fake test fixtures.
"""

import os
import uuid

# GT: id=SEC-GEN-001 type=TP rule=aws-access-token
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# GT: id=SEC-GEN-002 type=TP rule=github-pat
GITHUB_TOKEN = "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"

# GT: id=SEC-GEN-003 type=TP rule=slack-bot-token
SLACK_BOT_TOKEN = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"

# GT: id=SEC-GEN-004 type=TP rule=stripe-secret-key
STRIPE_API_KEY = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj"

# GT: id=SEC-GEN-005 type=TP rule=google-api-key
GOOGLE_API_KEY = "AIzaSyDummyKeyForBenchmarking01234567890"

# --- False Positive Traps ---

# GT: id=SEC-GEN-013 type=FP reason=generic-placeholder-text
SAMPLE_KEY_PLACEHOLDER = "YOUR_API_KEY_HERE"

# GT: id=SEC-GEN-014 type=FP reason=environment-variable-lookup
RESOLVED_SECRET = os.environ.get("AWS_SECRET_KEY", "default-fallback")

# GT: id=SEC-GEN-015 type=FP reason=standard-uuid4-string
USER_TRACKING_UUID = "550e8400-e29b-41d4-a716-446655440000"

# GT: id=SEC-GEN-016 type=FP reason=git-commit-sha-hash
DEPLOYED_COMMIT_SHA = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"

# GT: id=SEC-GEN-017 type=FP reason=sha256-file-integrity-checksum
CONTENT_CHECKSUM = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# GT: id=SEC-GEN-018 type=FP reason=explicit-mock-test-fixture
MOCK_TEST_CREDENTIAL = "mock_fake_test_fixture_only_key_00000000000000"

