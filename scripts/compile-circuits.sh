#!/bin/bash
# compile-circuits.sh — Compile the Circom ZKP identity circuit and produce the
# snarkjs artifacts needed by the Desktop Agent and Gateway.
#
# Prerequisites (install once):
#   npm install -g circom snarkjs
#
# Output files:
#   packages/desktop-agent/circuits/identity_js/identity.wasm  (proof generation)
#   packages/desktop-agent/circuits/identity_final.zkey        (proving key)
#   packages/gateway/src/config/zkp/verification_key.json      (verification key)

set -euo pipefail

CIRCUITS_DIR="packages/desktop-agent/circuits"
GATEWAY_ZKP_DIR="packages/gateway/src/config/zkp"
PTAU_FILE="powersoftau_final.ptau"

mkdir -p "$GATEWAY_ZKP_DIR"

echo "=== Step 1: Install circomlib dependencies ==="
(cd "$CIRCUITS_DIR" && npm install circomlib 2>/dev/null || true)

echo "=== Step 2: Compile identity.circom → identity.r1cs + identity.wasm ==="
circom "$CIRCUITS_DIR/identity.circom" \
    --r1cs "$CIRCUITS_DIR/identity.r1cs" \
    --wasm "$CIRCUITS_DIR" \
    --sym  "$CIRCUITS_DIR/identity.sym" \
    -l node_modules

echo "=== Step 3: Download Powers of Tau (Hermez 14) ==="
if [ ! -f "$PTAU_FILE" ]; then
    curl -L "https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_14.ptau" -o "$PTAU_FILE"
fi

echo "=== Step 4: Generate initial zkey ==="
snarkjs groth16 setup \
    "$CIRCUITS_DIR/identity.r1cs" \
    "$PTAU_FILE" \
    "$CIRCUITS_DIR/identity_0000.zkey"

echo "=== Step 5: Contribute randomness (non-interactive for dev) ==="
echo "verichain-dev-entropy" | snarkjs zkey contribute \
    "$CIRCUITS_DIR/identity_0000.zkey" \
    "$CIRCUITS_DIR/identity_final.zkey" \
    --name="VeriChain Dev"

echo "=== Step 6: Export verification key for Gateway ==="
snarkjs zkey export verificationkey \
    "$CIRCUITS_DIR/identity_final.zkey" \
    "$GATEWAY_ZKP_DIR/verification_key.json"

echo ""
echo "Done! Artifacts generated:"
echo "  $CIRCUITS_DIR/identity_js/identity.wasm"
echo "  $CIRCUITS_DIR/identity_final.zkey"
echo "  $GATEWAY_ZKP_DIR/verification_key.json"
echo ""
echo "The Desktop Agent dev-mode mock proof bypass is now inactive."
