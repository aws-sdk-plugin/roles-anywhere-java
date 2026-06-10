#!/usr/bin/env bash
# Generates all test certificate and encrypted PKCS8 key fixtures from scratch.
# Zero external dependencies beyond openssl.
#
# Usage: ./generate-encrypted-keys.sh [password] [output-dir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PASS="${1:-testpassword}"
DIR="${2:-${SCRIPT_DIR}}"

CIPHERS=(aes-128-cbc aes-192-cbc aes-256-cbc)
PRFS=(hmacWithSHA256 hmacWithSHA384 hmacWithSHA512)

# --- RSA key + self-signed cert ---

RSA_KEY="${DIR}/simple-leaf-key.pem"
RSA_CERT="${DIR}/simple-leaf.pem"

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$RSA_KEY"
echo "Generated $RSA_KEY"

openssl req -new -x509 -key "$RSA_KEY" -out "$RSA_CERT" \
    -days 3650 -subj "/CN=test-rsa"
echo "Generated $RSA_CERT"

# --- RSA encrypted keys: 3 ciphers × 3 PRFs + scrypt + DER ---

for cipher in "${CIPHERS[@]}"; do
  for prf in "${PRFS[@]}"; do
    out="${DIR}/encrypted-${cipher}-${prf}.pkcs8"
    openssl pkcs8 -topk8 -in "$RSA_KEY" -out "$out" \
        -passout "pass:$PASS" -v2 "$cipher" -v2prf "$prf"
    echo "Generated $out"
  done
done

out="${DIR}/encrypted-scrypt.pkcs8"
openssl pkcs8 -topk8 -in "$RSA_KEY" -out "$out" \
    -passout "pass:$PASS" -scrypt
echo "Generated $out"

out="${DIR}/encrypted-aes-256-cbc.der"
openssl pkcs8 -topk8 -in "$RSA_KEY" -outform DER -out "$out" \
    -passout "pass:$PASS" -v2 aes-256-cbc -v2prf hmacWithSHA256
echo "Generated $out"

# --- EC key + self-signed cert ---

EC_KEY="${DIR}/ec-leaf-key.pem"
EC_CERT="${DIR}/ec-leaf.pem"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$EC_KEY"
echo "Generated $EC_KEY"

openssl req -new -x509 -key "$EC_KEY" -out "$EC_CERT" \
    -days 3650 -subj "/CN=test-ec"
echo "Generated $EC_CERT"

# --- EC encrypted keys: 3 ciphers × 3 PRFs + scrypt ---

for cipher in "${CIPHERS[@]}"; do
  for prf in "${PRFS[@]}"; do
    out="${DIR}/encrypted-ec-${cipher}-${prf}.pkcs8"
    openssl pkcs8 -topk8 -in "$EC_KEY" -out "$out" \
        -passout "pass:$PASS" -v2 "$cipher" -v2prf "$prf"
    echo "Generated $out"
  done
done

out="${DIR}/encrypted-ec-scrypt.pkcs8"
openssl pkcs8 -topk8 -in "$EC_KEY" -out "$out" \
    -passout "pass:$PASS" -scrypt
echo "Generated $out"

out="${DIR}/encrypted-ec-aes-256-cbc.der"
openssl pkcs8 -topk8 -in "$EC_KEY" -outform DER -out "$out" \
    -passout "pass:$PASS" -v2 aes-256-cbc -v2prf hmacWithSHA256
echo "Generated $out"
