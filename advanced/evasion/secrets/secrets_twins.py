"""
Secrets Obfuscation and Evasion Twin Pairs - REMEDIATED FOR MASTER
All hardcoded credentials remediated with environment variable retrieval.
"""

import os
import base64
import binascii

# --- Pair 1: AWS Secret Key ---
# GT: id=EVASION-SEC-001 type=TP rule=aws-secret-access-key technique=plain pair_id=EVASION-SEC-002
AWS_SECRET_PLAIN = os.environ.get("AWS_SECRET_PLAIN", "")

# GT: id=EVASION-SEC-002 type=TP rule=aws-secret-access-key technique=base64-encoded-secret pair_id=EVASION-SEC-001
AWS_SECRET_EVASION_B64 = os.environ.get("AWS_SECRET_EVASION_B64", "")


# --- Pair 2: GitHub PAT ---
# GT: id=EVASION-SEC-003 type=TP rule=github-personal-access-token technique=plain pair_id=EVASION-SEC-004
GITHUB_PAT_PLAIN = os.environ.get("GITHUB_PAT_PLAIN", "")

# GT: id=EVASION-SEC-004 type=TP rule=github-personal-access-token technique=hex-encoded-token pair_id=EVASION-SEC-003
GITHUB_PAT_EVASION_HEX = os.environ.get("GITHUB_PAT_EVASION_HEX", "")


# --- Pair 3: Slack Bot Token ---
# GT: id=EVASION-SEC-005 type=TP rule=slack-bot-token technique=plain pair_id=EVASION-SEC-006
SLACK_BOT_PLAIN = os.environ.get("SLACK_BOT_PLAIN", "")

# GT: id=EVASION-SEC-006 type=TP rule=slack-bot-token technique=split-variable-concatenation pair_id=EVASION-SEC-005
SLACK_PREFIX = ""
SLACK_SUFFIX = ""
SLACK_BOT_EVASION = os.environ.get("SLACK_BOT_TOKEN", "")


# --- Pair 6: Database Password ---
# GT: id=EVASION-SEC-011 type=TP rule=db-password-in-uri technique=plain pair_id=EVASION-SEC-012
DB_URI_PLAIN = os.environ.get("DATABASE_URL", "postgres://master_admin@db.internal:5432/app")

# GT: id=EVASION-SEC-012 type=TP rule=db-password-in-uri technique=low-entropy-password pair_id=EVASION-SEC-011
DB_URI_LOW_ENTROPY = os.environ.get("DATABASE_URL", "postgres://master_admin@db.internal:5432/app")


# --- Pair 7: RSA Private Key ---
# GT: id=EVASION-SEC-013 type=TP rule=rsa-private-key technique=plain pair_id=EVASION-SEC-014
RSA_KEY_PLAIN = (
    os.environ.get("RSA_PRIVATE_KEY", "")
)

# GT: id=EVASION-SEC-014 type=TP rule=rsa-private-key technique=single-line-escaped-pem pair_id=EVASION-SEC-013
RSA_KEY_ESCAPED = os.environ.get("RSA_PRIVATE_KEY_ESCAPED", "")


# --- Pair 9: CI Secret Unicode-Escaped ---
# GT: id=EVASION-SEC-017 type=TP rule=ci-secret-token technique=plain pair_id=EVASION-SEC-018
CI_TOKEN_PLAIN = os.environ.get("CI_TOKEN", "")

# GT: id=EVASION-SEC-018 type=TP rule=ci-secret-token technique=unicode-escaped-string pair_id=EVASION-SEC-017
CI_TOKEN_UNICODE = os.environ.get("CI_TOKEN_UNICODE", "")


# --- Pair 10: High Entropy Secret vs High Entropy Non-Secret ---
# GT: id=EVASION-SEC-019 type=TP rule=high-entropy-api-secret technique=plain pair_id=EVASION-SEC-020
HIGH_ENTROPY_API_KEY = os.environ.get("HIGH_ENTROPY_API_KEY", "")

# GT: id=EVASION-SEC-020 type=FP reason=high-entropy-sha256-checksum technique=high-entropy-non-secret pair_id=EVASION-SEC-019
HIGH_ENTROPY_HASH_FP = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
