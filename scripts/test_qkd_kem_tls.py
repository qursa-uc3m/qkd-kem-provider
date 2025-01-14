import common
import sys
import os
import subprocess
import time
import pathlib

OQS_DIR = "/opt/oqs_openssl3"
CERTS_DIR = "./certs"

def get_test_env():
    """Set up the environment variables for OpenSSL and QKD-KEM provider"""
    # Get the project root directory
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Create environment dictionary starting with current environment
    env = os.environ.copy()
    
    # Set OpenSSL specific environment variables
    env.update({
        'OPENSSL_CONF': os.path.join(OQS_DIR, "oqs-provider/scripts/openssl-ca.cnf"),
        'OPENSSL_MODULES': os.path.join(project_dir, "_build/lib"),
        'PATH': os.path.join(OQS_DIR, ".local/bin") + os.pathsep + env.get('PATH', ''),
        'LD_LIBRARY_PATH': os.path.join(OQS_DIR, ".local/lib64") + os.pathsep + env.get('LD_LIBRARY_PATH', '')
    })
    
    return env

def setup_test_environment():
    """Setup paths for OpenSSL and certificates"""
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Setup paths
    ossl = os.path.join(OQS_DIR, ".local/bin/openssl")
    ossl_config = os.path.join(OQS_DIR, "oqs-provider/scripts/openssl-ca.cnf")
    
    return {
        'ossl': ossl,
        'ossl_config': ossl_config,
        'project_dir': project_dir
    }

def run_tls_test():
    """Run TLS test with QKD-KEM"""
    # Get environment and paths
    env = get_test_env()
    paths = setup_test_environment()
    
    kex_name = 'qkd_kyber768'
    server_port = 4433
    
    try:
        # Start server
        print("Starting server...")
        server_cmd = [
            paths['ossl'], 's_server',
            '-cert', os.path.join(paths['project_dir'], f'{CERTS_DIR}/rsa/rsa_2048_entity_cert.pem'),
            '-key', os.path.join(paths['project_dir'], f'{CERTS_DIR}/rsa/rsa_2048_entity_key.pem'),
            '-www',
            '-tls1_3',
            '-groups', kex_name,
            '-port', str(server_port),
            '-provider', 'default',
            '-provider', 'qkdkemprovider'
        ]
        
        print("Server command:", ' '.join(server_cmd))
        server = subprocess.Popen(server_cmd, env=env)
        
        # Give the server a moment to start
        time.sleep(2)
        
        # Run client
        print(f"\nRunning client with {kex_name}...")
        client_cmd = [
            paths['ossl'], 's_client',
            '-connect', f'localhost:{server_port}',
            '-groups', kex_name,
            '-provider', 'default',
            '-provider', 'qkdkemprovider'
        ]
        
        print("Client command:", ' '.join(client_cmd))
        client_output = common.run_subprocess(
            client_cmd,
            input='Q'.encode(),
            env=env
        )
        
        # Check result
        if "SSL handshake has read" in client_output:
            print(f"\nSuccess: TLS handshake completed successfully with {kex_name}")
            print("\nClient output:")
            print(client_output)
            return True
        else:
            print(f"\nError: TLS handshake failed with {kex_name}")
            print("\nClient output:")
            print(client_output)
            return False
            
    except Exception as e:
        print(f"\nError during test execution: {str(e)}")
        return False
    finally:
        # Cleanup
        if 'server' in locals():
            print("\nStopping server...")
            server.kill()

if __name__ == "__main__":
    success = run_tls_test()
    sys.exit(0 if success else 1)