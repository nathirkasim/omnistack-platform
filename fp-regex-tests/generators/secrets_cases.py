from typing import List
from .base import FixtureBuilder, TargetLine

def generate_secrets_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: SECRETS
    # -------------------------------------------------------------

    # 1. AWS Access Key ID (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/aws_access_key_flag.py")
    fb.add("import boto3").add()
    fb.add_target(
        'AWS_ACCESS_KEY_ID = "AKIA2Y8Z4W9V3X7R1T5M"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-001",
        "Direct literal assignment of valid-format AWS Access Key ID"
    )
    fb.add('client = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)')
    fixtures.append(fb)

    # 2. AWS Access Key Placeholder (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/aws_access_key_placeholder.py")
    fb.add("import boto3").add()
    fb.add_target(
        'AWS_ACCESS_KEY_ID = "YOUR_API_KEY_HERE"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-002",
        "Placeholder string representing template configuration"
    )
    fb.add('client = boto3.client("s3", aws_access_key_id=AWS_ACCESS_KEY_ID)')
    fixtures.append(fb)

    # 3. AWS Secret Access Key (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/aws_secret_key_flag.py")
    fb.add("import boto3").add()
    fb.add_target(
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYz8947KlMnP"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-003",
        "Hardcoded 40-character AWS secret access key literal"
    )
    fb.add('session = boto3.Session(aws_secret_access_key=AWS_SECRET_ACCESS_KEY)')
    fixtures.append(fb)

    # 4. AWS Secret Environment Lookup (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/aws_secret_env_lookup.py")
    fb.add("import os, boto3").add()
    fb.add_target(
        'AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-004",
        "Secure dynamic retrieval of secret key from environment"
    )
    fb.add('session = boto3.Session(aws_secret_access_key=AWS_SECRET_ACCESS_KEY)')
    fixtures.append(fb)

    # 5. GitHub Token (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/github_token_flag.js")
    fb.add("const https = require('https');").add()
    fb.add_target(
        'const token = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R";',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-005",
        "Valid-format personal access token literal"
    )
    fb.add("const headers = { Authorization: `token ${token}` };")
    fixtures.append(fb)

    # 6. GitHub Token Env (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/github_token_env.js")
    fb.add("const https = require('https');").add()
    fb.add_target(
        'const token = process.env.GITHUB_TOKEN;',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-006",
        "Environment variable reference for GitHub credential"
    )
    fb.add("const headers = { Authorization: `token ${token}` };")
    fixtures.append(fb)

    # 7. OpenAI API Key (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/openai_key_flag.py")
    fb.add("import requests").add()
    fb.add_target(
        'api_key = "sk-proj-abcde12345ABCDE12345abcde12345ABCDE12345abcde12"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-007",
        "Valid-format OpenAI API secret key literal"
    )
    fb.add('headers = {"Authorization": f"Bearer {api_key}"}')
    fixtures.append(fb)

    # 8. OpenAI API Key Placeholder (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/openai_key_placeholder.py")
    fb.add("import requests").add()
    fb.add_target(
        'api_key = "<your-token>"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-008",
        "Bracketed placeholder token string"
    )
    fb.add('headers = {"Authorization": f"Bearer {api_key}"}')
    fixtures.append(fb)

    # 9. Slack Bot Token (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/slack_token_flag.go")
    fb.add("package main").add('import "fmt"').add()
    fb.add_target(
        'var slackToken = "xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-009",
        "Valid-format Slack bot token string"
    )
    fb.add("func main() { fmt.Println(slackToken) }")
    fixtures.append(fb)

    # 10. Slack Token Env (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/slack_token_lookup.go")
    fb.add("package main").add('import ("fmt"; "os")').add()
    fb.add_target(
        'var slackToken = os.Getenv("SLACK_TOKEN")',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-010",
        "Environment variable lookup for Slack token"
    )
    fb.add("func main() { fmt.Println(slackToken) }")
    fixtures.append(fb)

    # 11. Stripe Live Secret Key (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/stripe_key_flag.js")
    fb.add("const stripe = require('stripe');").add()
    fb.add_target(
        'const stripeKey = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvW";',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-011",
        "Live Stripe production API secret key split across literals"
    )
    fb.add("const client = stripe(stripeKey);")
    fixtures.append(fb)

    # 12. Stripe Key Empty String (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/stripe_key_empty.js")
    fb.add("const stripe = require('stripe');").add()
    fb.add_target(
        'const stripeKey = "";',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-012",
        "Empty string initialization for credential variable"
    )
    fb.add("const client = stripe(stripeKey || process.env.STRIPE_KEY);")
    fixtures.append(fb)

    # 13. Google API Key (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/google_key_flag.py")
    fb.add("import urllib.request").add()
    fb.add_target(
        'api_key = "AIzaSyBv9x1d4E8f2G6h0J3k5L7m9N1p3Q5r7S"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-013",
        "Valid-format Google AIza API key literal"
    )
    fb.add('url = f"https://maps.googleapis.com/maps/api/geocode/json?key={api_key}"')
    fixtures.append(fb)

    # 14. Google Key Null/None (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/google_key_null.py")
    fb.add("api_key = None")
    fb.add_target(
        'google_maps_key = None',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-014",
        "Null value initialization representing unconfigured state"
    )
    fixtures.append(fb)

    # 15. RSA Private Key (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/rsa_private_key_flag.pem")
    fb.add_target(
        "-----BEGIN RSA PRIVATE KEY-----",
        "FLAG", "SECRETS", "L1_BASIC", "SEC-015",
        "PEM formatted RSA private key header"
    )
    fb.add("MIIEowIBAAKCAQEA0Y3y+9WzX8m9P7vK1t0sL6kQ2n8hZ1yU3bX7d8f9g4h2j5k6m7n8")
    fb.add("p9q0r1s2t3u4v5w6x7y8z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7s8t9u0v1w2")
    fb.add("-----END RSA PRIVATE KEY-----")
    fixtures.append(fb)

    # 16. RSA Public Key (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/rsa_public_key_noflag.pem")
    fb.add_target(
        "-----BEGIN PUBLIC KEY-----",
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-016",
        "PEM formatted public key containing non-secret cryptographic material"
    )
    fb.add("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0Y3y+9WzX8m9P7vK1t0sL6kQ")
    fb.add("-----END PUBLIC KEY-----")
    fixtures.append(fb)

    # 17. Postgres Connection String with Credentials (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/postgres_uri_flag.py")
    fb.add("import sqlalchemy").add()
    fb.add_target(
        'db_url = "postgres://admin:S3cr3tP4ss@db.internal:5432/app"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-017",
        "Database URI containing embedded cleartext credentials"
    )
    fb.add('engine = sqlalchemy.create_engine(db_url)')
    fixtures.append(fb)

    # 18. Localhost Connection String (DEBATABLE)
    fb = FixtureBuilder("l1_basic/secrets/postgres_uri_debatable.py")
    fb.add("import sqlalchemy").add()
    fb.add_target(
        'db_url = "postgres://user:password@localhost/db"',
        "DEBATABLE", "SECRETS", "L1_BASIC", "SEC-018",
        "Localhost database URI with standard dummy development credentials"
    )
    fb.add('engine = sqlalchemy.create_engine(db_url)')
    fixtures.append(fb)

    # 19. Password Literal (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/password_literal_flag.py")
    fb.add("auth_config = {}")
    fb.add_target(
        'password = "Tr0ub4dor&3xyz"',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-019",
        "Cleartext password assignment in configuration variable"
    )
    fb.add('auth_config["pass"] = password')
    fixtures.append(fb)

    # 20. Password Form Field / Label (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/password_form_field.py")
    fb.add("form_spec = {")
    fb.add_target(
        '    "field_type": "password",',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-020",
        "HTML input element type descriptor"
    )
    fb.add_target(
        '    "label": "Enter your password",',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-021",
        "UI form field user instruction label"
    )
    fb.add("}")
    fixtures.append(fb)

    # 21. Password Reference / File Path (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/password_reference.py")
    fb.add_target(
        'secret_name = "prod/db/credentials"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-022",
        "Cloud Secrets Manager resource path identifier"
    )
    fb.add_target(
        'password_file = "/run/secrets/db_password"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-023",
        "Filesystem path for container secret mount"
    )
    fixtures.append(fb)

    # 22. Variable Name Lookalikes (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/variable_name_lookalike.py")
    fb.add_target(
        'secretary = "Alice"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-024",
        "Sub-token secret match in unrelated English noun"
    )
    fb.add_target(
        'tokenizer = "bert-base-uncased"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-025",
        "NLP model tokenizer name"
    )
    fb.add_target(
        'keyboard = "us"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-026",
        "Hardware keyboard locale configuration"
    )
    fb.add_target(
        'passwordless = True',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-027",
        "Feature toggle boolean attribute"
    )
    fixtures.append(fb)

    # 23. High Entropy Non-Secrets (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/high_entropy_nonsecret.py")
    fb.add_target(
        'commit_sha = "b8a6f43e2d1c9b8a6f43e2d1c9b8a6f43e2d1c9b"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-028",
        "40-character hexadecimal git commit digest"
    )
    fb.add_target(
        'instance_id = "550e8400-e29b-41d4-a716-446655440000"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-029",
        "Standard RFC 4122 UUID string"
    )
    fb.add_target(
        'sha256_checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-030",
        "SHA-256 cryptographic hash of empty string"
    )
    fixtures.append(fb)

    # 24. Secret Split Across Concatenated Strings (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/secret_split_literal.js")
    fb.add("const service = require('./service');")
    fb.add_target(
        'const token = "ghp_" + "1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R";',
        "FLAG", "SECRETS", "L1_BASIC", "SEC-031",
        "Secret token split across concatenated string literals"
    )
    fb.add("service.init(token);")
    fixtures.append(fb)

    # 25. Secret in Heredoc (FLAG)
    fb = FixtureBuilder("l1_basic/secrets/secret_heredoc.sh")
    fb.add("#!/usr/bin/env bash")
    fb.add("cat <<EOF > /tmp/credentials")
    fb.add_target(
        "AKIA2Y8Z4W9V3X7R1T5M",
        "FLAG", "SECRETS", "L1_BASIC", "SEC-032",
        "AWS access key ID embedded within bash heredoc block"
    )
    fb.add("EOF")
    fixtures.append(fb)

    # 26. AWS Documented Sample Key (DEBATABLE)
    fb = FixtureBuilder("l1_basic/secrets/aws_doc_sample_debatable.py")
    fb.add("import boto3")
    fb.add_target(
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"',
        "DEBATABLE", "SECRETS", "L1_BASIC", "SEC-033",
        "Official AWS documentation sample access key ID"
    )
    fb.add_target(
        'AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
        "DEBATABLE", "SECRETS", "L1_BASIC", "SEC-034",
        "Official AWS documentation sample secret access key"
    )
    fixtures.append(fb)

    # 27. Wrong Length Lookalike (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/wrong_length_lookalike.py")
    fb.add_target(
        'short_token = "ghp_12345678"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-035",
        "GitHub token prefix with insufficient length"
    )
    fb.add_target(
        'short_key = "AKIA12345678"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-036",
        "AWS key prefix with only 12 characters instead of 20"
    )
    fixtures.append(fb)

    # 28. Substring in Longer Identifier (NO_FLAG)
    fb = FixtureBuilder("l1_basic/secrets/longer_identifier_prefix.py")
    fb.add_target(
        'RAKIAAKIAKIAFOO = "constant_resource_name"',
        "NO_FLAG", "SECRETS", "L1_BASIC", "SEC-037",
        "Identifier containing AKIA sub-string without boundary anchors"
    )
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: SECRETS
    # -------------------------------------------------------------

    # L2-1: Token Registry in Python (Lookalikes vs real issue)
    fb = FixtureBuilder("l2_intermediate/secrets/token_registry.py")
    fb.add("import os")
    fb.add("from dataclasses import dataclass").add()
    fb.add("@dataclass")
    fb.add("class TokenMetrics:")
    fb.add_target(
        '    token_count: int = 100',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-001",
        "Integer count metric variable with token substring"
    )
    fb.add_target(
        '    author_key_count: int = 42',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-002",
        "Integer author count with key substring"
    )
    fb.add_target(
        '    token_type: str = "Bearer"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-003",
        "Standard RFC 6750 authorization scheme type name"
    )
    fb.add().add("class SecurityRegistry:")
    fb.add_target(
        '    secret_name = "production/auth/service-credentials"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-004",
        "Cloud provider secret catalog path name"
    )
    fb.add_target(
        '    placeholder = "REPLACE_ME"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-005",
        "Generic configuration placeholder string"
    )
    fb.add_target(
        '    s3_etag = "d41d8cd98f00b204e9800998ecf8427e"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-006",
        "32-hexadecimal S3 object ETag digest"
    )
    fb.add_target(
        '    docker_digest = "sha256:45b23dee08af5e43a7fa6c4e1e99d63e3173956d2974b29463e4e656d11f67f9"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-007",
        "OCI container image digest reference"
    )
    fb.add("    def get_token(self):")
    fb.add_target(
        '        return os.environ.get("SERVICE_API_TOKEN")',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-008",
        "Environment variable lookup for service token"
    )
    fb.add().add("def initialize_sync():")
    fb.add_target(
        '    static_auth_token = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-009",
        "Hardcoded GitHub personal access token assigned inline"
    )
    fb.add("    return static_auth_token")
    fixtures.append(fb)

    # L2-2: Credential Store in .env
    fb = FixtureBuilder("l2_intermediate/secrets/credential_store.env")
    fb.add("# Application Runtime Configuration")
    fb.add("APP_NAME=auth-broker")
    fb.add("APP_PORT=8080")
    fb.add_target(
        'DB_PASSWORD=${DB_PASSWORD}',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-010",
        "Shell variable expansion placeholder in environment file"
    )
    fb.add_target(
        'API_KEY=YOUR_API_KEY_HERE',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-011",
        "Standard documentation template placeholder value"
    )
    fb.add_target(
        'TOKEN_SECRET=changeme',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-012",
        "Well-known template value indicating uninitialized token"
    )
    fb.add_target(
        'SECRETS_DIR=/run/secrets/credentials',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-013",
        "Container filesystem mount path for secrets"
    )
    fb.add_target(
        'CACHE_ETAG=33a64df551425fcc55e4d42a148795d9f25f89d4',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-014",
        "Hexadecimal cache fingerprint digest"
    )
    fb.add_target(
        'DATABASE_PASSWORD=Tr0ub4dor&3xyz',
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-015",
        "Exposed plaintext database password literal"
    )
    fb.add_target(
        'SLACK_BOT_TOKEN=xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-016",
        "Hardcoded live Slack bot token literal"
    )
    fb.add_target(
        'PASSWORD_EMPTY=""',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-017",
        "Empty double-quoted password variable"
    )
    fixtures.append(fb)

    # L2-3: Format Robustness in Python
    fb = FixtureBuilder("l2_intermediate/secrets/format_robustness.py")
    fb.add("# Format variations for regex parser verification")
    fb.add_target(
        'key="ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-018",
        "Token assignment without whitespace around operator"
    )
    fb.add_target(
        "key = 'ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R'",
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-019",
        "Token literal enclosed in single quotation marks"
    )
    fb.add_target(
        'KEY = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-020",
        "Uppercase variable identifier with secret token"
    )
    fb.add_target(
        'api_secret = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvW" # operational credential',
        "FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-021",
        "Secret assignment followed by trailing inline comment"
    )
    fb.add_target(
        'ak = "RAKIAAKIAKIAFOO"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-022",
        "Repetitive substring lookalike without matching length"
    )
    fb.add_target(
        'short_ak = "AKIA12345678"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-023",
        "Truncated key length not matching AWS key specification"
    )
    fb.add_target(
        'placeholder_bracket = "${API_KEY}"',
        "NO_FLAG", "SECRETS", "L2_INTERMEDIATE", "SEC-L2-024",
        "Template interpolation placeholder syntax"
    )
    fixtures.append(fb)

    return fixtures
