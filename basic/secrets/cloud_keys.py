"""
Cloud and Service Credentials Configuration (Synthetic Test Fixtures) - REMEDIATED FOR MASTER
All credentials and tokens in this file have been remediated:
Hardcoded values replaced with secure environment variable lookups.
"""

import os
import uuid

# GT: id=SEC-GEN-001 type=TP rule=aws-access-token
AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

# GT: id=SEC-GEN-002 type=TP rule=github-pat
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# GT: id=SEC-GEN-003 type=TP rule=slack-bot-token
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")

# GT: id=SEC-GEN-004 type=TP rule=stripe-secret-key
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY", "")

# GT: id=SEC-GEN-005 type=TP rule=google-api-key
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY", "")

# GT: id=SEC-GEN-025 type=TP rule=sendgrid-api-key
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY", "")

# GT: id=SEC-GEN-026 type=TP rule=twilio-account-credentials
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")

# GT: id=SEC-GEN-027 type=TP rule=openai-api-key
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")

# GT: id=SEC-GEN-028 type=TP rule=gitlab-personal-access-token
GITLAB_PAT = os.environ.get("GITLAB_PAT", "")

# GT: id=SEC-GEN-029 type=TP rule=slack-incoming-webhook
SLACK_WEBHOOK_URL = os.environ.get("SLACK_WEBHOOK_URL", "")

# GT: id=SEC-GEN-030 type=TP rule=mongodb-connection-uri
MONGODB_URI = os.environ.get("MONGODB_URI", "")

# GT: id=SEC-GEN-031 type=TP rule=redis-auth-uri
REDIS_URL = os.environ.get("REDIS_URL", "")

# GT: id=SEC-GEN-032 type=TP rule=github-fine-grained-pat
GITHUB_FINE_GRAINED_TOKEN = os.environ.get("GITHUB_FINE_GRAINED_TOKEN", "")

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

# GT: id=SEC-GEN-033 type=FP reason=twilio-test-account-sid
TWILIO_TEST_SID = os.environ.get("TWILIO_TEST_SID", "")

# GT: id=SEC-GEN-034 type=FP reason=stripe-test-key
STRIPE_TEST_KEY = os.environ.get("STRIPE_TEST_KEY", "")

# GT: id=SEC-GEN-035 type=FP reason=example-documentation-webhook
DOCS_WEBHOOK_URL = os.environ.get("DOCS_WEBHOOK_URL", "")

# GT: id=SEC-GEN-036 type=FP reason=ssh-public-key-string
SSH_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7bL9kL2mP5qR8tU1vW4xY7zA0bC3dE6 test-key@localhost"
