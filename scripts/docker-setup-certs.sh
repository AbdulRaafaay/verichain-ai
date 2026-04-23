#!/bin/sh
set -e

# Path to the certs directory
CERTS_DIR="/certs"

# Ensure we can reach the internet
echo "Checking internet connectivity..."
until ping -c 1 google.com > /dev/null 2>&1; do
    echo "Waiting for internet access to install openssl..."
    sleep 2
done

# Install openssl
echo "Installing openssl..."
apk add --no-cache openssl

if [ ! -f "$CERTS_DIR/gateway.crt" ]; then
    echo "Certificates missing. Generating..."
    
    # 1. Generate CA
    openssl genrsa -out $CERTS_DIR/ca.key 2048
    openssl req -new -x509 -nodes -days 365 -key $CERTS_DIR/ca.key -out $CERTS_DIR/ca.crt -subj "/CN=VeriChainCA"
    
    # 2. Generate Gateway Certificate (for Nginx and Gateway)
    openssl genrsa -out $CERTS_DIR/gateway.key 2048
    openssl req -new -key $CERTS_DIR/gateway.key -out $CERTS_DIR/gateway.csr -subj "/CN=localhost"
    openssl x509 -req -in $CERTS_DIR/gateway.csr -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key -CAcreateserial -out $CERTS_DIR/gateway.crt -days 365
    
    # 3. Generate Dashboard Certificate (for Nginx)
    openssl genrsa -out $CERTS_DIR/dashboard.key 2048
    openssl req -new -key $CERTS_DIR/dashboard.key -out $CERTS_DIR/dashboard.csr -subj "/CN=localhost"
    openssl x509 -req -in $CERTS_DIR/dashboard.csr -CA $CERTS_DIR/ca.crt -CAkey $CERTS_DIR/ca.key -CAcreateserial -out $CERTS_DIR/dashboard.crt -days 365
    
    echo "Certificates generated successfully."
else
    echo "Certificates already exist."
fi
