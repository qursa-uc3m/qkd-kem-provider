#!/bin/bash

BASE_DIR="$(pwd)"

# Set up all required environment variables
export OPENSSL_APP=openssl
export OPENSSL_MODULES="${BASE_DIR}/_build/lib"
export OPENSSL_CONF="${BASE_DIR}/test/openssl-ca.cnf"

# Set up library paths
if [ -d "${BASE_DIR}/.local/lib64" ]; then
    export LD_LIBRARY_PATH="${BASE_DIR}/.local/lib64"
elif [ -d "${BASE_DIR}/.local/lib" ]; then
    export LD_LIBRARY_PATH="${BASE_DIR}/.local/lib"
fi

# Set OSX specific library path if needed
if [ -z "${DYLD_LIBRARY_PATH}" ]; then
    export DYLD_LIBRARY_PATH="${LD_LIBRARY_PATH}"
fi

# Print test setup
echo "Test setup:"
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
echo "OPENSSL_APP=${OPENSSL_APP}"
echo "OPENSSL_CONF=${OPENSSL_CONF}"
echo "OPENSSL_MODULES=${OPENSSL_MODULES}"
if uname -s | grep -q "^Darwin"; then
    echo "DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}"
fi

# Run KEM tests
run_kem_test() {
    echo "Running KEM tests..."
    
    if [ ! -f "_build/test/oqs_test_kems" ]; then
        echo "❌ Test binary not found"
        return 1
    fi

    cd _build/test
    echo "Running from directory: $(pwd)"

    ./oqs_test_kems "oqsprovider" "${OPENSSL_CONF}"
    local result=$?
    
    cd "${BASE_DIR}"
    
    if [ $result -eq 0 ]; then
        echo "✅ KEM tests passed"
    else
        echo "❌ KEM tests failed"
        echo "Return code: $result"
    fi
    
    return $result
}

# Run the tests
run_kem_test

exit $?