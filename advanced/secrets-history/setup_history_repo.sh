#!/usr/bin/env bash
# Script to create a standalone git repository with realistic history for testing git-aware scanners.
set -euo pipefail

TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/history-repo"
rm -rf "$TARGET_DIR"
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"

git init -b main
git config user.name "Security Benchmark Bot"
git config user.email "bot@example.com"

# Commit 1: Initial commit with AWS key (to be deleted later)
echo 'AWS_SECRET_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"' > creds.txt
git add creds.txt
git commit -m "feat: add initial cloud credentials"
C1_SHA=$(git rev-parse HEAD)

# Commit 2: Remove secret (secret is deleted from HEAD, but remains in git history)
echo 'AWS_SECRET_KEY="${AWS_SECRET_KEY}"' > creds.txt
git add creds.txt
git commit -m "fix: remove hardcoded AWS secret from codebase"

# Commit 3: Rotate Stripe key (old secret remains in commit history)
echo 'STRIPE_KEY="sk_live_old_rotated_key_9876543210123456789"' > stripe.env
git add stripe.env
git commit -m "feat: configure Stripe billing secret"
echo 'STRIPE_KEY="sk_live_new_rotated_key_1234567890abcdef123456789"' > stripe.env
git add stripe.env
git commit -m "security: rotate Stripe key to new generation"

# Commit 4: Create branch with secret, merge without secret, delete branch
git checkout -b feature/auth-prototype
echo 'GITHUB_PAT="ghp_HistorySecretToken012345678901234567"' > prototype_token.txt
git add prototype_token.txt
git commit -m "prototype: add GitHub personal access token for test integration"
git checkout main
git branch -D feature/auth-prototype

# Commit 5: Move secret between files (config.py -> app.py)
echo 'MIGRATED_SECRET="db_password_migrated_between_modules_987654"' > config.py
git add config.py
git commit -m "feat: add database password in config module"
git rm config.py
echo 'MIGRATED_SECRET="db_password_migrated_between_modules_987654"' > app.py
git add app.py
git commit -m "refactor: relocate database password from config to app"

echo "[OK] Created synthetic git repository with history in $TARGET_DIR"
