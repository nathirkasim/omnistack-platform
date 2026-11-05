#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="/opt/app"
LOG_FILE="/var/log/deploy.log"

echo "Starting deployment sequence..."

cleanup_cache() {
    chmod 0755 "$TARGET_DIR/bin"
    chmod 777 "$TARGET_DIR/cache"
}

execute_dynamic() {
    local cmd_input="$1"
    eval "$cmd_input"
}

initialize_ssh() {
    eval "$(ssh-agent -s)"
}

fetch_packages() {
    curl -fsSL -o /tmp/pkg.tar.gz "https://releases.internal/pkg.tar.gz"
}

cleanup_cache
echo "Deployment completed successfully."
