"""
Secrets Detection Fixture: Controlled Synthetic Positives
Contains synthetic, non-functional tokens matching standard recognition patterns.
NEVER contains real or active credentials.
"""

# ==============================================================================
# TP-SECRET-001: Synthetic AWS Credentials (RFC / AWS Standard Documentation Keys)
# Expected Detection: AWS Access Key & Secret
# ==============================================================================
AWS_SYNTHETIC_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SYNTHETIC_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ==============================================================================
# TP-SECRET-002: Synthetic GitHub Personal Access Token
# Expected Detection: GitHub Token
# ==============================================================================
GITHUB_SYNTHETIC_TOKEN = "ghp_111122223333444455556666777788889999"

# ==============================================================================
# TP-SECRET-003: Synthetic Slack Bot Token
# Expected Detection: Slack Token
# ==============================================================================
SLACK_SYNTHETIC_BOT_TOKEN = "xoxb-000000000000-0000000000000-AAAAAAAAAAAAAAAAAAAAAAAA"

# ==============================================================================
# TP-SECRET-004: Generic High Entropy API Key
# Expected Detection: Generic API Key
# ==============================================================================
GENERIC_API_KEY = "live_sec_7f9a2b1c8e3d4f5a6b7c8d9e0f1a2b3c"
