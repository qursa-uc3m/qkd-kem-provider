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
# Check if backend is ETSI 004 Python client
elif [ "${QKD_BACKEND}" = "python_client" ]; then
    echo "Setting up ETSI 004 Python Client environment:"
    conda deactivate

    # Ensure LD_LIBRARY_PATH doesn't include conda's lib path
    export LD_LIBRARY_PATH=/usr/local/lib:/opt/oqs_openssl3/.local/lib64

    # Set PYTHONHOME to system Python
    export PYTHONHOME=/usr
    export PYTHONPATH=/usr/lib/python3/dist-packages
    
    # Find the QUBIP ETSI-QKD-004 directory - adjust path as needed
    # This assumes it's in the same parent directory as your project
    #QUBIP_DIR="$(cd ${PROJECT_DIR}/../etsi-qkd-004 &> /dev/null && pwd)"
    QUBIP_DIR="" # set your certificates path here
    if [ ! -d "${QUBIP_DIR}" ]; then
        echo "Warning: QUBIP ETSI-QKD-004 directory not found at ${QUBIP_DIR}"
        echo "Please enter path to QUBIP directory:"
        read QUBIP_DIR
    fi
    
    # Certificate paths
    export QKD_CERT_DIR="${QUBIP_DIR}/certs"
    export QKD_CLIENT_CERT_PEM="${QKD_CERT_DIR}/client_cert_localhost.pem"
    export QKD_CLIENT_CERT_KEY="${QKD_CERT_DIR}/client_key_localhost.pem"
    export QKD_SERVER_CERT_PEM="${QKD_CERT_DIR}/server_cert_localhost.pem"
    
    # Server addresses
    export QKD_SERVER_ALICE_ADDRESS="https://localhost:25575/api"
    export QKD_SERVER_BOB_ADDRESS="https://localhost:25576/api"
    
    # SAE identifiers
    export QKD_ALICE_SAE_ID="alice_sae_1"
    export QKD_BOB_SAE_ID="bob_sae_1"
    
    # Skip certificate verification for testing
    export QKD_VERIFY_CERT="False"
    
    # Debug level
    export QKD_DEBUG_LEVEL=4
    
    # Python module and paths
    export PYTHONPATH="${PYTHONPATH}:${HOME}/.local/lib/qkd"
    
    echo "ETSI 004 Python Client environment set:"
    echo "QKD_SERVER_ALICE_ADDRESS=$QKD_SERVER_ALICE_ADDRESS"
    echo "QKD_SERVER_BOB_ADDRESS=$QKD_SERVER_BOB_ADDRESS"
    echo "QKD_ALICE_SAE_ID=$QKD_ALICE_SAE_ID"
    echo "QKD_BOB_SAE_ID=$QKD_BOB_SAE_ID"
    echo "QKD_CLIENT_CERT_PEM=$QKD_CLIENT_CERT_PEM"
    echo "QKD_CLIENT_CERT_KEY=$QKD_CLIENT_CERT_KEY"
    echo "QKD_SERVER_CERT_PEM=$QKD_SERVER_CERT_PEM"
    echo "QKD_VERIFY_CERT=$QKD_VERIFY_CERT"
    echo "QKD_DEBUG_LEVEL=$QKD_DEBUG_LEVEL"
    echo "PYTHONPATH updated to include: ${HOME}/.local/lib/qkd"
    
    # For OpenSSL testing, we need to map these to the corresponding QKD-KEM values
    # This allows the same code to work with both ETSI 004 and ETSI 014
    export QKD_MASTER_KME_HOSTNAME="${QKD_SERVER_ALICE_ADDRESS}"
    export QKD_SLAVE_KME_HOSTNAME="${QKD_SERVER_BOB_ADDRESS}"
    export QKD_MASTER_SAE="${QKD_ALICE_SAE_ID}"
    export QKD_SLAVE_SAE="${QKD_BOB_SAE_ID}"
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