#!/bin/bash

# Default parameters
OQS_DIR="/opt/oqs_openssl3"
QKD_CERTS_DIR=""

# Print usage information
function show_usage {
    echo "Usage: source $0 [-o OQS_DIR] [-c QKD_CERTS_DIR]"
    echo "Options:"
    echo "  -o    Set OpenSSL installation directory (default: /opt/oqs_openssl3)"
    echo "  -c    Set QKD certificates directory (required for python_client backend)"
    echo ""
    echo "Examples:"
    echo "  source $0 -o /custom/openssl/path -c /path/to/qkd/certs"
    echo "  QKD_BACKEND=python_client source $0 -c /path/to/qkd/certs"
    return 0
}

# Parse command line arguments
while getopts "o:c:h" opt; do
    case "$opt" in
        o) OQS_DIR="$OPTARG" ;;
        c) QKD_CERTS_DIR="$OPTARG" ;;
        h) show_usage; return 0 ;;
        *) echo "Invalid option: -$OPTARG"; show_usage; return 1 ;;
    esac
done
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
    #conda deactivate

    # Ensure LD_LIBRARY_PATH doesn't include conda's lib path
    export LD_LIBRARY_PATH=/usr/local/lib:/opt/oqs_openssl3/.local/lib64

    # Set PYTHONHOME to system Python
    export PYTHONHOME=/usr
    export PYTHONPATH=/usr/lib/python3/dist-packages
    
    # Check if QKD_CERTS_DIR is provided when using python_client backend
    if [ -z "${QKD_CERTS_DIR}" ]; then
        echo "ERROR: QKD certificates directory not provided."
        echo "When using the python_client backend, you must specify a certificate directory with -c flag."
        echo "Example: QKD_BACKEND=python_client source $0 -c /path/to/qkd/certs"
        return 1
    fi
    
    if [ ! -d "${QKD_CERTS_DIR}" ]; then
        echo "ERROR: Directory '${QKD_CERTS_DIR}' does not exist."
        echo "Please provide a valid path to your QKD certificates directory."
        return 1
    fi
    
    # Certificate paths
    export CLIENT_CERT_PEM="${QKD_CERTS_DIR}/client_cert_localhost.pem"
    export CLIENT_CERT_KEY="${QKD_CERTS_DIR}/client_key_localhost.pem"
    export SERVER_CERT_PEM="${QKD_CERTS_DIR}/server_cert_localhost.pem"

    export SERVER_ADDRESS="localhost"
    export SERVER_PORT="25576"
    export CLIENT_ADDRESS="localhost"
    export CLIENT_PORT="25575"

    export QKD_MASTER_KME_HOSTNAME="localhost"  # Alice's hostname only
    export QKD_SLAVE_KME_HOSTNAME="localhost"   # Bob's hostname only
    export QKD_MASTER_SAE="alice_sae_1"
    export QKD_SLAVE_SAE="bob_sae_1"

    export KEY_INDEX=0
    export METADATA_SIZE=1024

    # QoS parameters
    export QOS_KEY_CHUNK_SIZE=32
    export QOS_MAX_BPS=40000
    export QOS_MIN_BPS=5000
    export QOS_JITTER=10
    export QOS_PRIORITY=0
    export QOS_TIMEOUT=5000
    export QOS_TTL=3600
    
    # Debug level
    export QKD_DEBUG_LEVEL=4
    
    # Python module and paths
    export PYTHONPATH="${PYTHONPATH}:${HOME}/.local/lib/qkd"
    
    echo "ETSI 004 Python Client environment set:"
    echo "QKD_SERVER_ALICE_ADDRESS=$SERVER_ADDRESS"
    echo "QKD_SERVER_BOB_ADDRESS=$CLIENT_ADDRESS"
    echo "QKD_CLIENT_CERT_PEM=$CLIENT_CERT_PEM"
    echo "QKD_CLIENT_CERT_KEY=$CLIENT_CERT_KEY"
    echo "QKD_SERVER_CERT_PEM=$SERVER_CERT_PEM"
    echo "QKD_DEBUG_LEVEL=$QKD_DEBUG_LEVEL"
    echo "PYTHONPATH updated to include: ${HOME}/.local/lib/qkd"
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