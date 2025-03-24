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

# Check if CERBERIS_XGR is enabled
if [ "${QKD_BACKEND}" = "qukaydee" ]; then
    echo "Setting up QuKayDee environment:"
    
    # Certificate configuration
    export QKD_MASTER_CA_CERT_PATH="${PROJECT_DIR}/qkd_certs/account-${ACCOUNT_ID}-server-ca-qukaydee-com.crt"
    export QKD_SLAVE_CA_CERT_PATH="${PROJECT_DIR}/qkd_certs/account-${ACCOUNT_ID}-server-ca-qukaydee-com.crt"

    export QKD_MASTER_CERT_PATH="${PROJECT_DIR}/qkd_certs/sae-1.crt"
    export QKD_MASTER_KEY_PATH="${PROJECT_DIR}/qkd_certs/sae-1.key"

    export QKD_SLAVE_CERT_PATH="${PROJECT_DIR}/qkd_certs/sae-2.crt"
    export QKD_SLAVE_KEY_PATH="${PROJECT_DIR}/qkd_certs/sae-2.key"
    
    # QuKayDee configuration
    if [ -z "${ACCOUNT_ID}" ]; then
        echo "Warning: ACCOUNT_ID not set. Please set your QuKayDee account ID."
    else
        export QKD_MASTER_KME_HOSTNAME="https://kme-1.acct-${ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
        export QKD_SLAVE_KME_HOSTNAME="https://kme-2.acct-${ACCOUNT_ID}.etsi-qkd-api.qukaydee.com"
        export QKD_MASTER_SAE="sae-1"
        export QKD_SLAVE_SAE="sae-2"
        
        echo "QKD_MASTER_KME_HOSTNAME=$QKD_MASTER_KME_HOSTNAME"
        echo "QKD_SLAVE_KME_HOSTNAME=$QKD_SLAVE_KME_HOSTNAME"
    fi
else
    echo "Using default QKD backend (simulated) with simulated URIs"
    echo "Check if the URIS are being set correctly for your backend"
    export QKD_MASTER_KME_HOSTNAME="http://simulated-master.kme.local"
    export QKD_SLAVE_KME_HOSTNAME="http://simulated-slave.kme.local"
    export QKD_MASTER_SAE="simulated-master-sae"
    export QKD_SLAVE_SAE="simulated-slave-sae"
    
    echo "QKD_MASTER_KME_HOSTNAME=$QKD_MASTER_KME_HOSTNAME"
    echo "QKD_SLAVE_KME_HOSTNAME=$QKD_SLAVE_KME_HOSTNAME"
    echo "QKD_MASTER_SAE=$QKD_MASTER_SAE"
    echo "QKD_SLAVE_SAE=$QKD_SLAVE_SAE"
fi