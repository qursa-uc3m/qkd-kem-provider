#!/bin/bash

# Default installation directory
OQS_INSTALL_DIR="/opt/oqs_openssl3"
PROVIDERS_DIR="/usr/local/lib/ossl-modules"

# Export OpenSSL binary location and provider path
export OPENSSL="${OQS_INSTALL_DIR}/.local/bin/openssl"
export PROVIDER_PATH="$PROVIDERS_DIR"

# Set library and binary paths
export LD_LIBRARY_PATH="${OQS_INSTALL_DIR}/.local/lib64:$LD_LIBRARY_PATH"
export PATH="${OQS_INSTALL_DIR}/.local/bin:$PATH"

# Print current settings
echo "Environment variables set:"
echo "OPENSSL=$OPENSSL"
echo "PROVIDER_PATH=$PROVIDER_PATH"
echo "LD_LIBRARY_PATH includes: ${OQS_INSTALL_DIR}/.local/lib64"
echo "PATH includes: ${OQS_INSTALL_DIR}/.local/bin"