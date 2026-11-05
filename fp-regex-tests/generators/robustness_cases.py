from typing import List
from .base import FixtureBuilder, TargetLine

def generate_robustness_cases() -> List[FixtureBuilder]:
    fixtures: List[FixtureBuilder] = []

    # -------------------------------------------------------------
    # L1 BASIC: ROBUSTNESS
    # -------------------------------------------------------------

    # 1. Secret in Comment (DEBATABLE)
    fb = FixtureBuilder("l1_basic/robustness/rob_secret_in_comment_debatable.py")
    fb.add("# Configuration notes for operations team")
    fb.add_target(
        '# AWS_ACCESS_KEY_ID = "AKIA2Y8Z4W9V3X7R1T5M"',
        "DEBATABLE", "ROBUSTNESS", "L1_BASIC", "ROB-001",
        "AWS credential string located solely inside Python code comment"
    )
    fb.add('API_URL = "https://api.internal.net"')
    fixtures.append(fb)

    # 2. Keyword Inside String Literal (NO_FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_keyword_in_string_noflag.py")
    fb.add("import logging")
    fb.add("logger = logging.getLogger(__name__)")
    fb.add_target(
        'logger.info("User prompt: enter your password at the prompt")',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-002",
        "Sensitive keyword occurrence inside constant log format message"
    )
    fixtures.append(fb)

    # 3. Partial Token in Longer Identifier (NO_FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_partial_match_noflag.py")
    fb.add_target(
        'author_key_count = 15',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-003",
        "Identifier containing key substring with alphanumeric prefixes and suffixes"
    )
    fb.add_target(
        'passwordless_enabled = True',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-004",
        "Compound noun containing password without representing a secret"
    )
    fb.add_target(
        'RAKIAAKIAKIAFOO = "static_resource_pointer"',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-005",
        "Substring containing AKIA repeated within identifier"
    )
    fixtures.append(fb)

    # 4. Mixed CRLF Line Endings (FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_mixed_crlf.py", eol="\r\n")
    fb.add("import os")
    fb.add_target(
        'AWS_ACCESS_KEY_ID = "AKIA2Y8Z4W9V3X7R1T5M"',
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-006",
        "Valid credential line terminated with Windows CRLF carriage returns"
    )
    fixtures.append(fb)

    # 5. UTF-8 Characters Adjacent to Tokens (FLAG & NO_FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_utf8_neighbors.py")
    fb.add("# -*- coding: utf-8 -*-")
    fb.add("# 認証キー設定 / 🔐 Secure Token Definition / Σύστημα")
    fb.add_target(
        'token_label = "APIキー: YOUR_API_KEY_HERE"',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-007",
        "Multilingual label with placeholder token"
    )
    fb.add_target(
        'API_KEY = "AIzaSyBv9x1d4E8f2G6h0J3k5L7m9N1p3Q5r7S"  # 外部連携用',
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-008",
        "Valid Google API key followed by CJK unicode comment"
    )
    fixtures.append(fb)

    # 6. UTF-8 Byte Order Mark (BOM) at File Start (FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_bom_header.py", has_bom=True)
    fb.add("# File encoded with UTF-8 BOM")
    fb.add_target(
        'ACCESS_TOKEN = "ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R"',
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-009",
        "Valid token inside file containing UTF-8 BOM prefix"
    )
    fixtures.append(fb)

    # 7. Non-standard Extension .env.local (FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_unusual_ext.env.local")
    fb.add("# Local developer overrides")
    fb.add_target(
        'LOCAL_GITHUB_TOKEN=ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R',
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-010",
        "Credential located in dotfile with compound secondary extension"
    )
    fixtures.append(fb)

    # 8. Non-standard Extension .conf (NO_FLAG & FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_service.conf")
    fb.add("[database]")
    fb.add_target(
        'password_file = /etc/secrets/db_password',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-011",
        "Path reference to password in configuration file"
    )
    fb.add_target(
        'admin_token = xoxb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx',
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-012",
        "Cleartext Slack token inside .conf file"
    )
    fixtures.append(fb)

    # 9. Markdown Documentation Code Fence (NO_FLAG / DEBATABLE)
    fb = FixtureBuilder("l1_basic/robustness/rob_markdown_docs.md")
    fb.add("# API Integration Guide")
    fb.add("To invoke the service, pass your authorization header:")
    fb.add("```bash")
    fb.add_target(
        'curl -H "Authorization: Bearer YOUR_API_KEY_HERE" https://api.service.com/v1',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-013",
        "Documentation code fence with placeholder token"
    )
    fb.add_target(
        'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
        "DEBATABLE", "ROBUSTNESS", "L1_BASIC", "ROB-014",
        "Documentation code fence containing official AWS sample key"
    )
    fb.add("```")
    fixtures.append(fb)

    # 10. Long Minified JavaScript Line (>10k chars) (FLAG & NO_FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_minified_bundle.js")
    padding = "var _0x1a2b='abcdefghijklmnopqrstuvwxyz0123456789';" * 180
    fb.add_target(
        f'{padding}const secretToken="ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R";console.log("ready");',
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-015",
        "Secret embedded inside 10,000+ character minified JavaScript line"
    )
    fixtures.append(fb)

    # 11. Windows File Path Lookalikes (NO_FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_windows_paths.py")
    fb.add("import os")
    fb.add_target(
        r'PASSWORD_STORE = "C:\\ProgramData\\Application\\secrets\\db_password.txt"',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-016",
        "Windows backslash file path to password file"
    )
    fb.add_target(
        r'CERT_STORE = "C:\\Windows\\System32\\drivers\\etc\\secrets"',
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-017",
        "Windows system directory path reference"
    )
    fixtures.append(fb)

    # 12. YAML Block Scalar >- (FLAG & NO_FLAG)
    fb = FixtureBuilder("l1_basic/robustness/rob_yaml_block_scalar.yaml")
    fb.add("config:")
    fb.add("  placeholder_key: >-")
    fb.add_target(
        "    YOUR_API_KEY_HERE",
        "NO_FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-018",
        "Multiline block scalar containing template placeholder"
    )
    fb.add("  hardcoded_secret: >-")
    fb.add_target(
        "    ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R",
        "FLAG", "ROBUSTNESS", "L1_BASIC", "ROB-019",
        "Multiline block scalar containing live personal access token"
    )
    fixtures.append(fb)

    # -------------------------------------------------------------
    # L2 INTERMEDIATE: ROBUSTNESS
    # -------------------------------------------------------------

    # L2-1: Multilingual Comments and String Literals in Python
    fb = FixtureBuilder("l2_intermediate/robustness/multilingual_comments_and_strings.py")
    fb.add("# -*- coding: utf-8 -*-")
    fb.add("# Internationalized logging and authentication metadata")
    fb.add("class LocaleManager:")
    fb.add_target(
        '    # TODO: rotate key ghp_1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7q8R',
        "DEBATABLE", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-001",
        "Real token inside developer task comment"
    )
    fb.add_target(
        '    password_label = "ユーザーのパスワードを入力してください"',
        "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-002",
        "Japanese text containing translation of word password"
    )
    fb.add_target(
        '    help_text = "Enter password or leave blank for passwordless access"',
        "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-003",
        "English user documentation string containing password keywords"
    )
    fb.add_target(
        '    token_regex = r"^[A-Za-z0-9_]{32}$"',
        "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-004",
        "Regular expression pattern definition matching 32-character tokens"
    )
    fb.add_target(
        '    live_stripe_key = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvW"',
        "FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-005",
        "Active Stripe live API credential in production class attribute"
    )
    fb.add("    def get_token(self):")
    fb.add_target(
        '        return "REPLACE_ME"',
        "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-006",
        "Placeholder value in method return"
    )
    fixtures.append(fb)

    # L2-2: Terraform JSON (.tf.json) Format
    fb = FixtureBuilder("l2_intermediate/robustness/unusual_formats.tf.json")
    fb.add("{")
    fb.add('  "resource": {')
    fb.add('    "aws_security_group_rule": {')
    fb.add('      "open_ssh": {')
    fb.add('        "type": "ingress",')
    fb.add('        "from_port": 22,')
    fb.add('        "to_port": 22,')
    fb.add('        "protocol": "tcp",')
    fb.add('        "security_group_id": "sg-0123456789abcdef0",')
    fb.add_target(
        '        "cidr_blocks": ["0.0.0.0/0"]',
        "FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-007",
        "Open SSH rule defined via Terraform JSON syntax"
    )
    fb.add("      },")
    fb.add('      "internal_ssh": {')
    fb.add('        "type": "ingress",')
    fb.add('        "from_port": 22,')
    fb.add('        "to_port": 22,')
    fb.add('        "protocol": "tcp",')
    fb.add('        "security_group_id": "sg-0123456789abcdef0",')
    fb.add_target(
        '        "cidr_blocks": ["10.0.0.0/8"]',
        "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-008",
        "Internal SSH rule defined via Terraform JSON syntax"
    )
    fb.add("      }")
    fb.add("    },")
    fb.add('    "aws_ebs_volume": {')
    fb.add('      "data_volume": {')
    fb.add('        "availability_zone": "us-east-1a",')
    fb.add('        "size": 50,')
    fb.add_target(
        '        "encrypted": true',
        "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-L2-009",
        "Encrypted volume attribute in JSON format"
    )
    fb.add("      }")
    fb.add("    }")
    fb.add("  }")
    fb.add("}")
    fixtures.append(fb)

    # L2-3: Repetition and Volume Stress Test
    fb = FixtureBuilder("l2_intermediate/robustness/repetition_stress.py")
    fb.add("# Volume stress fixture testing parser deduplication and false alarm rate")
    fb.add("class VolumeMetrics:")
    for i in range(1, 11):
        fb.add_target(
            f'    metric_token_{i} = "token_hash_{i:04d}"',
            "NO_FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", f"ROB-REP-{i:03d}",
            f"Repetitive token name lookalike attribute index {i}"
        )
    fb.add_target(
        '    LIVE_API_KEY = "AKIA2Y8Z4W9V3X7R1T5M"',
        "FLAG", "ROBUSTNESS", "L2_INTERMEDIATE", "ROB-REP-099",
        "Real AWS credential embedded amidst repetitive lookalikes"
    )
    fixtures.append(fb)

    return fixtures
