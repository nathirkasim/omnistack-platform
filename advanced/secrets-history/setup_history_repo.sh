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
echo 'AWS_SECRET_KEY="4fB8qW2mN9kL5pT7vX1yZ3aC6eH0jR8uI4oP2sT1"' > creds.txt
git add creds.txt
git commit -m "feat: add initial cloud credentials"
C1_SHA=$(git rev-parse HEAD)

# Commit 2: Remove secret (secret is deleted from HEAD, but remains in git history)
echo 'AWS_SECRET_KEY="${AWS_SECRET_KEY}"' > creds.txt
git add creds.txt
git commit -m "fix: remove hardcoded AWS secret from codebase"

# Commit 3: Rotate Stripe key (old secret remains in commit history)
echo 'STRIPE_KEY="sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj"' > stripe.env
git add stripe.env
git commit -m "feat: configure Stripe billing secret"
echo 'STRIPE_KEY="sk_live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789AbCdEfGhIj"' > stripe.env
git add stripe.env
git commit -m "security: rotate Stripe key to new generation"

# Commit 4: Create branch with secret, merge without secret, delete branch
git checkout -b feature/auth-prototype
echo 'GITHUB_PAT="ghp_8uK2mP5qR8tU1vW4xY7zA0bC3dE6fG8hI0jK"' > prototype_token.txt
git add prototype_token.txt
git commit -m "prototype: add GitHub personal access token for test integration"
git checkout main
git branch -D feature/auth-prototype

# Commit 5: Move secret between files (config.py -> app.py)
echo 'MIGRATED_SECRET="postgres://db_admin:K9%23mP2%24vW8%21xZ4%5EqL7@db.internal:5432/main"' > config.py
git add config.py
git commit -m "feat: add database password in config module"
git rm config.py
echo 'MIGRATED_SECRET="postgres://db_admin:K9%23mP2%24vW8%21xZ4%5EqL7@db.internal:5432/main"' > app.py
git add app.py
git commit -m "refactor: relocate database password from config to app"

echo "[OK] Created synthetic git repository with history in $TARGET_DIR"
