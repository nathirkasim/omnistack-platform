"""
Cloud and Service Credentials Configuration (Synthetic Test Fixtures)
All credentials and tokens in this file are strictly fake test fixtures
crafted to match production security scanner regular expressions.
"""

import os
import uuid

# GT: id=SEC-GEN-001 type=TP rule=aws-access-token
AWS_ACCESS_KEY_ID = "AKIA2VNZW5XY89LM4Q7R"
AWS_SECRET_ACCESS_KEY = "4fB8qW2mN9kL5pT7vX1yZ3aC6eH0jR8uI4oP2sT1"

# GT: id=SEC-GEN-002 type=TP rule=github-pat
GITHUB_TOKEN = "ghp_9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK"

# GT: id=SEC-GEN-003 type=TP rule=slack-bot-token
SLACK_BOT_TOKEN = "xoxb-9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK"

# GT: id=SEC-GEN-004 type=TP rule=stripe-secret-key
STRIPE_API_KEY = "sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj"

# GT: id=SEC-GEN-005 type=TP rule=google-api-key
GOOGLE_API_KEY = "AIzaSyB8uK2mP5qR8tU1vW4xY7zA0bC3dE6fG8h"

# GT: id=SEC-GEN-025 type=TP rule=sendgrid-api-key
SENDGRID_API_KEY = "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"

# GT: id=SEC-GEN-026 type=TP rule=twilio-account-credentials
TWILIO_ACCOUNT_SID = "AC7b8c9d0e1f2a3b4c5d6e7f8a9b0c1z9k"
TWILIO_AUTH_TOKEN = "9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8h"

# GT: id=SEC-GEN-027 type=TP rule=openai-api-key
OPENAI_API_KEY = "sk-proj-9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK2mN5qR8tU1vW4xY7zA0bC3dE6fG8"

# GT: id=SEC-GEN-028 type=TP rule=gitlab-personal-access-token
GITLAB_PAT = "glpat_k9L2mP5qR8tU1vW4xY7z"

# GT: id=SEC-GEN-029 type=TP rule=slack-incoming-webhook
SLACK_WEBHOOK_URL = "https://hooks.slack.com/workflows/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"

# GT: id=SEC-GEN-030 type=TP rule=mongodb-connection-uri
MONGODB_URI = "mongodb+srv://clusterAdmin:9kL2mP5qR8tU1vW4@cluster0.a1b2c.mongodb.net/production?retryWrites=true&w=majority"

# GT: id=SEC-GEN-031 type=TP rule=redis-auth-uri
REDIS_URL = "redis://:8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c@prod-cache-redis.internal:6379/0"

# GT: id=SEC-GEN-032 type=TP rule=github-fine-grained-pat
GITHUB_FINE_GRAINED_TOKEN = "github_pat_11AYZ3K4A012345678_9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK2mN5qR8tU1vW4xY7zA0bC3dE6fG8h"

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
TWILIO_TEST_SID = "AC00000000000000000000000000000000"

# GT: id=SEC-GEN-034 type=FP reason=stripe-test-key
STRIPE_TEST_KEY = "sk_test_51OzK9pL2mN5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK2mN5qR8tU"

# GT: id=SEC-GEN-035 type=FP reason=example-documentation-webhook
DOCS_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"

# GT: id=SEC-GEN-036 type=FP reason=ssh-public-key-string
SSH_PUBLIC_KEY = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7bL9kL2mP5qR8tU1vW4xY7zA0bC3dE6 test-key@localhost"
