#!/usr/bin/env bash
set -e

ENV_FILE=".devcontainer/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "Generating devcontainer secrets in $ENV_FILE..."
  mkdir -p "$(dirname "$ENV_FILE")"
  cat > "$ENV_FILE" <<EOF
# Auto-generated devcontainer secrets. These are local-development values only.
# Regenerate them anytime with: rm .devcontainer/.env && devcontainer rebuild
NIVRIT_AUTH_SECRET=$(openssl rand -base64 32)
NIVRIT_TOTP_ENCRYPTION_KEY=$(openssl rand -base64 32)
NIVRIT_SIGNING_KEY_SEED=$(openssl rand -base64 32)
EOF
fi
