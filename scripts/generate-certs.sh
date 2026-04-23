#!/bin/bash
# VeriChain AI — mTLS Certificate Generation Script
# Generates Root CA and service-specific certificates.

set -e

CERT_DIR="./certs"
mkdir -p $CERT_DIR

echo "Generating Root CA..."
openssl genrsa -out $CERT_DIR/ca.key 4096
openssl req -x509 -new -nodes -key $CERT_DIR/ca.key -sha256 -days 3650 -out $CERT_DIR/ca.crt \
    -subj "/C=US/ST=State/L=City/O=VeriChainAI/CN=VeriChain-Root-CA"

echo "Generating Security Gateway Certificate..."
openssl genrsa -out $CERT_DIR/gateway.key 2048
openssl req -new -key $CERT_DIR/gateway.key -out $CERT_DIR/gateway.csr \
    -subj "/C=US/ST=State/L=City/O=VeriChainAI/CN=gateway"
openssl x509 -req -in $CERT_DIR/gateway.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key \
    -CAcreateserial -out $CERT_DIR/gateway.crt -days 365 -sha256

echo "Generating Trust Dashboard Certificate..."
openssl genrsa -out $CERT_DIR/dashboard.key 2048
openssl req -new -key $CERT_DIR/dashboard.key -out $CERT_DIR/dashboard.csr \
    -subj "/C=US/ST=State/L=City/O=VeriChainAI/CN=dashboard"
openssl x509 -req -in $CERT_DIR/dashboard.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key \
    -CAcreateserial -out $CERT_DIR/dashboard.crt -days 365 -sha256

echo "Generating Client Certificate (for Desktop Agent mTLS)..."
openssl genrsa -out $CERT_DIR/client.key 2048
openssl req -new -key $CERT_DIR/client.key -out $CERT_DIR/client.csr \
    -subj "/C=US/ST=State/L=City/O=VeriChainAI/CN=desktop-agent"
openssl x509 -req -in $CERT_DIR/client.csr -CA $CERT_DIR/ca.crt -CAkey $CERT_DIR/ca.key \
    -CAcreateserial -out $CERT_DIR/client.crt -days 365 -sha256

# Cleanup CSRs
rm $CERT_DIR/*.csr
rm $CERT_DIR/*.srl

echo "Certificates generated in $CERT_DIR"
ls -lh $CERT_DIR
