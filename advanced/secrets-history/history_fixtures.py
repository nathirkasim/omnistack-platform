"""
Git History and CI Secret Fixtures
Contains targets for git history commit scanning and false positive traps.
"""
import os

# GT: id=SEC-HIST-001 type=TP rule=git-history-committed-then-deleted
GIT_HISTORY_DELETED_AWS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

# GT: id=SEC-HIST-002 type=TP rule=git-history-deleted-branch-secret
GIT_HISTORY_BRANCH_PAT = os.environ.get("GITHUB_TOKEN", "")

# GT: id=SEC-HIST-003 type=TP rule=git-history-rotated-stale-secret
GIT_HISTORY_ROTATED_STRIPE_KEY = os.environ.get("STRIPE_API_KEY", "")

# GT: id=SEC-HIST-004 type=TP rule=git-history-secret-moved-files
GIT_HISTORY_MOVED_SECRET = os.environ.get("DATABASE_URL", "")

# --- False Positive Traps ---

# GT: id=SEC-HIST-027 type=FP reason=commit-sha-hash
DEPLOY_COMMIT_REF = "7b2d5a8e1f0c3b4a6d8e9f0a1b2c3d4e5f6a7b8c"

# GT: id=SEC-HIST-028 type=FP reason=package-lock-integrity-checksum
LOCKFILE_INTEGRITY = "sha512-4yPzFqK5G9v3J1p7r8s9t0u1v2w3x4y5z6A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6=="

# GT: id=SEC-HIST-029 type=FP reason=mock-test-fixture-token
MOCK_FIXTURE_KEY = "mock_test_token_not_real_key_0000000000"

# GT: id=SEC-HIST-030 type=FP reason=env-example-template-string
CONFIG_TEMPLATE_VALUE = "API_KEY=YOUR_API_KEY_HERE"
