#!/usr/bin/env bash
# gen-dev-tls.sh — emit a self-signed cert pair for the compose edge service.
# Never use these certs anywhere except a developer workstation.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
tls_dir="$root/deployments/compose/edge/tls"
mkdir -p "$tls_dir"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$tls_dir/privkey.pem" \
  -out    "$tls_dir/fullchain.pem" \
  -days 365 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  > /dev/null 2>&1

chmod 600 "$tls_dir/privkey.pem"
echo "wrote self-signed cert to $tls_dir (valid 365d, CN=localhost)"
