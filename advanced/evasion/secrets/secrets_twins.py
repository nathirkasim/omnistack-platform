"""
Secrets Obfuscation and Evasion Twin Pairs
10 paired cases linking plain form credentials with evasive representations.
"""

import base64
import binascii

# --- Pair 1: AWS Secret Key ---
# GT: id=EVASION-SEC-001 type=TP rule=aws-secret-access-key technique=plain pair_id=EVASION-SEC-002
AWS_SECRET_PLAIN = "4fB8qW2mN9kL5pT7vX1yZ3aC6eH0jR8uI4oP2sT1"

# GT: id=EVASION-SEC-002 type=TP rule=aws-secret-access-key technique=base64-encoded-secret pair_id=EVASION-SEC-001
AWS_SECRET_EVASION_B64 = "NGZCOHFXMm1OOWtMNXBUN3ZYMXlaM2FDNmVIMGpSOHVJNG9QMnNUMQ=="


# --- Pair 2: GitHub PAT ---
# GT: id=EVASION-SEC-003 type=TP rule=github-personal-access-token technique=plain pair_id=EVASION-SEC-004
GITHUB_PAT_PLAIN = "ghp_9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK"

# GT: id=EVASION-SEC-004 type=TP rule=github-personal-access-token technique=hex-encoded-token pair_id=EVASION-SEC-003
GITHUB_PAT_EVASION_HEX = "6768705f396b4c326d50357152387455317657347859377a41306243336445366647386849306a4b"


# --- Pair 3: Slack Bot Token ---
# GT: id=EVASION-SEC-005 type=TP rule=slack-bot-token technique=plain pair_id=EVASION-SEC-006
SLACK_BOT_PLAIN = "xoxb-9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK"

# GT: id=EVASION-SEC-006 type=TP rule=slack-bot-token technique=split-variable-concatenation pair_id=EVASION-SEC-005
SLACK_PREFIX = "xoxb-"
SLACK_SUFFIX = "9kL2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK"
SLACK_BOT_EVASION = SLACK_PREFIX + SLACK_SUFFIX


# --- Pair 6: Database Password ---
# GT: id=EVASION-SEC-011 type=TP rule=db-password-in-uri technique=plain pair_id=EVASION-SEC-012
DB_URI_PLAIN = "postgres://master_admin:K9%23mP2%24vW8%21xZ4%5EqL7@db.internal:5432/app"

# GT: id=EVASION-SEC-012 type=TP rule=db-password-in-uri technique=low-entropy-password pair_id=EVASION-SEC-011
DB_URI_LOW_ENTROPY = "postgres://master_admin:passw0rd123@db.internal:5432/app"


# --- Pair 7: RSA Private Key ---
# GT: id=EVASION-SEC-013 type=TP rule=rsa-private-key technique=plain pair_id=EVASION-SEC-014
RSA_KEY_PLAIN = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3t8XbZ3wU9qKxY8sZb6t8jB1Z2v3m4k5l6o7p8q9r0s1t2
-----END RSA PRIVATE KEY-----"""

# GT: id=EVASION-SEC-014 type=TP rule=rsa-private-key technique=single-line-escaped-pem pair_id=EVASION-SEC-013
RSA_KEY_ESCAPED = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEA0Y3t8XbZ3wU9qKxY8sZb6t8jB1Z2v3m4k5l6o7p8q9r0s1t2\\n-----END RSA PRIVATE KEY-----"


# --- Pair 9: CI Secret Unicode-Escaped ---
# GT: id=EVASION-SEC-017 type=TP rule=ci-secret-token technique=plain pair_id=EVASION-SEC-018
CI_TOKEN_PLAIN = "glpat_k9L2mP5qR8tU1vW4xY7z"

# GT: id=EVASION-SEC-018 type=TP rule=ci-secret-token technique=unicode-escaped-string pair_id=EVASION-SEC-017
CI_TOKEN_UNICODE = "\u0067\u006c\u0070\u0061\u0074\u005f\u006b\u0039\u004c\u0032\u006d\u0050\u0035\u0071\u0052\u0038\u0074\u0055\u0031\u0076\u0057\u0034\u0078\u0059\u0037\u007a"


# --- Pair 10: High Entropy Secret vs High Entropy Non-Secret ---
# GT: id=EVASION-SEC-019 type=TP rule=high-entropy-api-secret technique=plain pair_id=EVASION-SEC-020
HIGH_ENTROPY_API_KEY = "live_sec_7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a"

# GT: id=EVASION-SEC-020 type=FP reason=high-entropy-sha256-checksum technique=high-entropy-non-secret pair_id=EVASION-SEC-019
HIGH_ENTROPY_HASH_FP = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
