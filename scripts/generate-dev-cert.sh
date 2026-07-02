#!/usr/bin/env bash
set -euo pipefail

# Generate a self-signed certificate/key pair for local HTTPS development.
# In production, use a proper CA-issued certificate (Let's Encrypt, etc.).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${SCRIPT_DIR}/../certs"

mkdir -p "${CERT_DIR}"

cd "${CERT_DIR}"

if [ -f dev.crt ] && [ -f dev.key ]; then
    echo "Existing dev.crt and dev.key found in ${CERT_DIR}; skipping generation."
    exit 0
fi

openssl req -x509 \
    -newkey rsa:2048 \
    -keyout dev.key \
    -out dev.crt \
    -days 365 \
    -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Generated ${CERT_DIR}/dev.crt and ${CERT_DIR}/dev.key"
