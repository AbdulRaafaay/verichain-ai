#!/bin/sh
set -e

CERTS_DIR="/certs"

echo "Installing openssl..."
apk add --no-cache openssl

if [ ! -f "$CERTS_DIR/gateway.crt" ]; then
    echo "Certificates missing. Generating..."

    # 1. CA
    openssl genrsa -out $CERTS_DIR/ca.key 2048
    openssl req -new -x509 -nodes -days 365 -key $CERTS_DIR/ca.key \
        -out $CERTS_DIR/ca.crt -subj "/CN=VeriChainCA"

    # 2. Gateway certificate (used by the Gateway HTTPS server and Nginx)
    openssl genrsa -out $CERTS_DIR/gateway.key 2048
    openssl req -new -key $CERTS_DIR/gateway.key \
        -out $CERTS_DIR/gateway.csr -subj "/CN=localhost"
    openssl x509 -req -in $CERTS_DIR/gateway.csr \
        -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key -CAcreateserial \
        -out $CERTS_DIR/gateway.crt -days 365

    # 3. Dashboard certificate (used by Nginx for the Trust Dashboard SSL listener)
    openssl genrsa -out $CERTS_DIR/dashboard.key 2048
    openssl req -new -key $CERTS_DIR/dashboard.key \
        -out $CERTS_DIR/dashboard.csr -subj "/CN=localhost"
    openssl x509 -req -in $CERTS_DIR/dashboard.csr \
        -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key -CAcreateserial \
        -out $CERTS_DIR/dashboard.crt -days 365

    # 4. Client certificate (used by the Desktop Agent for mTLS)
    openssl genrsa -out $CERTS_DIR/client.key 2048
    openssl req -new -key $CERTS_DIR/client.key \
        -out $CERTS_DIR/client.csr -subj "/CN=desktop-agent"
    openssl x509 -req -in $CERTS_DIR/client.csr \
        -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key -CAcreateserial \
        -out $CERTS_DIR/client.crt -days 365

    echo "All certificates generated successfully."
else
    echo "Certificates already exist. Skipping generation."
fi
