#!/bin/bash

# Default installation directory
OQS_DIR="/opt/oqs_openssl3"

# Allow custom directory via command line argument
if [ "$1" != "" ]; then
    OQS_DIR="$1"
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Get the project root directory (two levels up from scripts/)
PROJECT_DIR="$( cd "$SCRIPT_DIR/.." &> /dev/null && pwd )"



# Export environment variables
export OPENSSL_CONF="${OQS_DIR}/oqs-provider/scripts/openssl-ca.cnf"
export OPENSSL_MODULES="${PROJECT_DIR}/_build/lib"
export PATH="${OQS_DIR}/.local/bin:$PATH"
export LD_LIBRARY_PATH="${OQS_DIR}/.local/lib64:$LD_LIBRARY_PATH"

# Print the current settings
echo "Environment variables set:"
echo "OPENSSL_CONF=$OPENSSL_CONF"
echo "OPENSSL_MODULES=$OPENSSL_MODULES"
echo "PATH updated to include: ${OQS_DIR}/.local/bin"
echo "LD_LIBRARY_PATH updated to include: ${OQS_DIR}/.local/lib64"