#!/bin/bash

BASE_DIR="$(pwd)"

# Help function
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo "Run OQS KEM and/or TLS Group tests"
    echo ""
    echo "Options:"
    echo "  -k, --kem        Run KEM tests"
    echo "  -g, --groups     Run TLS Group tests"
    echo "  -p, --params     Run EVP PKEY params tests"
    echo "  -a, --all        Run all tests"
    echo "  -h, --help       Show this help message"
    echo ""
    echo "Example: $0 --all"
}

# Set up environment variables
setup_environment() {
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
}

# Print test setup
print_setup() {
    echo "Test setup:"
    echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
    echo "OPENSSL_APP=${OPENSSL_APP}"
    echo "OPENSSL_CONF=${OPENSSL_CONF}"
    echo "OPENSSL_MODULES=${OPENSSL_MODULES}"
    if uname -s | grep -q "^Darwin"; then
        echo "DYLD_LIBRARY_PATH=${DYLD_LIBRARY_PATH}"
    fi
}

# Run KEM tests
run_kem_test() {
    echo "Running KEM tests..."
    
    if [ ! -f "_build/test/oqs_test_kems" ]; then
        echo "❌ Test binary not found"
        return 1
    fi

    cd _build/test
    echo "Running from directory: $(pwd)"

    ./oqs_test_kems "qkdkemprovider" "${OPENSSL_CONF}"
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

# Run TLS Group tests
run_group_test() {
    echo "Running TLS Group tests..."
    
    if [ ! -f "_build/test/oqs_test_groups" ]; then
        echo "❌ TLS Group test binary not found"
        return 1
    fi

    cd _build/test
    echo "Running from directory: $(pwd)"

    CERT_DIR="${BASE_DIR}/test"
    
    OPENSSL_DEBUG=yes ./oqs_test_groups "qkdkemprovider" "${OPENSSL_CONF}" "${CERT_DIR}"
    local result=$?
    
    cd "${BASE_DIR}"
    
    if [ $result -eq 0 ]; then
        echo "✅ TLS Group tests passed"
    else
        echo "❌ TLS Group tests failed"
        echo "Return code: $result"
    fi
    
    return $result
}

# Run EVP PKEY params tests
run_params_test() {
    echo "Running EVP PKEY params tests..."
    
    if [ ! -f "_build/test/oqs_test_evp_pkey_params" ]; then
        echo "❌ EVP PKEY params test binary not found"
        return 1
    fi

    cd _build/test
    echo "Running from directory: $(pwd)"

    echo "Running EVP PKEY params tests with CH=$QKD_KEY_ID_CH"
    
    ./oqs_test_evp_pkey_params "qkdkemprovider" "${OPENSSL_CONF}"
    local result=$?
    
    cd "${BASE_DIR}"
    
    if [ $result -eq 0 ]; then
        echo "✅ EVP PKEY params tests passed"
    else
        echo "❌ EVP PKEY params tests failed"
        echo "Return code: $result"
    fi
    
    return $result
}

main() {
    local run_kem=0
    local run_groups=0
    local run_params=0
    local run_bench=0
    local bench_iterations=0
    local exit_status=0

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -k|--kem)
                run_kem=1
                shift
                ;;
            -b|--bench)
                run_bench=1
                shift
                if [[ $# -gt 0 && $1 =~ ^[0-9]+$ ]]; then
                    bench_iterations=$1
                    shift
                else
                    echo "Error: --bench requires a number of iterations"
                    show_help
                    exit 1
                fi
                ;;
            -g|--groups)
                run_groups=1
                shift
                ;;
            -p|--params)
                run_params=1
                shift
                ;;
            -a|--all)
                run_kem=1
                run_groups=1
                run_params=1
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    # If no options specified, show help
    if [ $run_kem -eq 0 ] && [ $run_groups -eq 0 ] && [ $run_params -eq 0 ] && [ $run_bench -eq 0 ]; then
        show_help
        exit 1
    fi

    # Setup environment
    setup_environment
    print_setup

    # Run selected tests
    if [ $run_kem -eq 1 ]; then
        echo "==============================================="
        echo "Starting KEM Tests"
        echo "==============================================="
        run_kem_test
        local kem_status=$?
        [ $kem_status -ne 0 ] && exit_status=1
    fi

    if [ $run_groups -eq 1 ]; then
        echo "==============================================="
        echo "Starting TLS Group Tests"
        echo "==============================================="
        run_group_test
        local group_status=$?
        [ $group_status -ne 0 ] && exit_status=1
    fi

    if [ $run_params -eq 1 ]; then
        echo "==============================================="
        echo "Starting EVP PKEY Params Tests"
        echo "==============================================="
        run_params_test
        local params_status=$?
        [ $params_status -ne 0 ] && exit_status=1
    fi

    # Print final summary
    echo "==============================================="
    echo "Test Summary:"
    if [ $run_kem -eq 1 ]; then
        if [ $kem_status -eq 0 ]; then
            echo "KEM Tests: ✅ PASSED"
        else
            echo "KEM Tests: ❌ FAILED"
        fi
    fi
    if [ $run_groups -eq 1 ]; then
        if [ $group_status -eq 0 ]; then
            echo "TLS Group Tests: ✅ PASSED"
        else
            echo "TLS Group Tests: ❌ FAILED"
        fi
    fi
    if [ $run_params -eq 1 ]; then
        if [ $params_status -eq 0 ]; then
            echo "EVP PKEY Params Tests: ✅ PASSED"
        else
            echo "EVP PKEY Params Tests: ❌ FAILED"
        fi
    fi
    if [ $run_bench -eq 1 ]; then
        if [ $bench_status -eq 0 ]; then
            echo "KEM Benchmarks: ✅ COMPLETED"
        else
            echo "KEM Benchmarks: ❌ FAILED"
        fi
    fi
    echo "==============================================="

    return $exit_status
}

# Execute main with all arguments
main "$@"