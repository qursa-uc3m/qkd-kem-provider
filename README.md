# QKD-KEM Provider

This (work in progress) fork implements hybrid key encapsulation mechanisms combining quantum key distribution (QKD) with post-quantum cryptography in OpenSSL 3.0. The implementation extends the [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) to enable concurrent use of QKD-derived keys alongside post-quantum KEM operations.

For build instructions and usage details, see the oqs-provider [0.7.0 README](https://github.com/open-quantum-safe/oqs-provider/blob/0.7.0/README.md).

## About the Project

This work is part of the QURSA (Quantum-based Resistant Architectures and Techniques) project, developed through collaboration between:

- Information and Computing Laboratory (I&CLab), Department of Telematic Engineering, Universidade de Vigo (UVigo)
- Pervasive Computing Laboratory, Department of Telematic Engineering, Universidad Carlos III de Madrid (UC3M)

## Protocol Overview

For detailed information about the protocol specification, including the key generation, encapsulation, and decapsulation processes, please see our [Protocol Documentation](docs/protocol.md).

## Dependencies

This project requires our [QKD ETSI API](https://github.com/qursa-uc3m/qkd-etsi-api) implementation, which provides the interface for quantum key distribution operations according to ETSI standards.

Moreover, this project also requires [liboqs](https://github.com/open-quantum-safe/liboqs) and [OpenSSL](https://github.com/openssl/openssl).

This project has been successfully tested with the following dependencies and environment:

- liboqs: 0.12.0
- OpenSSL: 3.4.0
- Ubuntu: 24.04.1 LTS (Noble) and Ubuntu 22.04.5 LTS both with kernel 6.8.0-51-generic.

## Installation

## Installing the QKD ETSI API

```bash
git clone https://github.com/qursa-uc3m/qkd-etsi-api
cd qkd-etsi-api
mkdir build
cd build
cmake -DENABLE_ETSI004=OFF -DENABLE_ETSI014=ON -DQKD_BACKE
ND=simulated -DBUILD_TESTS=ON ..
make
sudo make install
```

## Installing OpenSSL and the oqs-provider

First install OpenSSL and oqs-provider using the provided scripts:

```bash
# Install OpenSSL
./scripts/install_openssl3.sh

# Install oqs-provider
./scripts/install_oqsprovider.sh
```

The scripts install OpenSSL `openssl-3.4.0` and oqs-provider `0.8.0` to `/opt/oqs_openssl3`. Use `-p` flag to specify a different installation path.

## Installing the QKD-KEM Provider

Clone the repository and build the project:

```bash
git clone https://github.com/qursa-uc3m/qkd-kem-provider
cd qkd-kem-provider
```

To build the provider for the first time run

```bash
export LIBOQS_BRANCH="0.12.0"
export OQSPROV_CMAKE_PARAMS="-DQKD_KEY_ID_CH=OFF"
./scripts/fullbuild.sh -F
```

and then just

```bash
export OQSPROV_CMAKE_PARAMS="-DQKD_KEY_ID_CH=OFF"
./scripts/fullbuild.sh -f
```

## Running the tests

Before running any tests, set up the environment variables to use the installed OpenSSL, oqs-provider, and QKD-KEM provider:

```bash
source ./scripts/oqs_env.sh
```

### Functional Tests

```bash
./scripts/runtests.sh
```

We have also added a script to run individual tests:

Run only KEM tests

```bash
./run_oqs_tests.sh --kem
```

Run only TLS Group tests

```bash
./run_oqs_tests.sh --groups
```

### Testing QKD-KEM Parameters with QuKayDee Backend

Set up your QuKayDee account environment variables:

```bash
export QKD_BACKEND=qukaydee
export ACCOUNT_ID=2509  # Replace with your account ID
```

Source the OpenSSL environment script:

```bash
source ./scripts/oqs_env.sh
```

Build the provider with QKD support enabled:

```bash
export OQSPROV_CMAKE_PARAMS="-DQKD_KEY_ID_CH=ON"
export LIBOQS_BRANCH="0.12.0"
./scripts/fullbuild.sh -f
```

```bash
./run_oqs_tests.sh --params
```

### Testing QKD-KEM Provider with QUBIP's ETSI 004 client

For ETSI 004 support through the QKD-KEM Provider, see the [QKD ETSI API C Wrapper README](https://github.com/qursa-uc3m/qkd-etsi-api-c-wrapper). You can find the general setup instructions there.


One thing to note is that we have to modify the `docker-compose.yml` so both server containers reference the localhost certificates:

```yaml
services:
  qkd_server_alice:
    build: ./server
    container_name: qkd_server_alice
    environment:
      - SERVER_CERT_PEM=/certs/server_cert_localhost.pem  # Server public key
      - SERVER_CERT_KEY=/certs/server_key_localhost.pem  # Server private key
      - CLIENT_CERT_PEM=/certs/client_cert_localhost.pem  # Client public key
      # Keep the rest unchanged

  qkd_server_bob:
    build: ./server
    container_name: qkd_server_bob
    environment:
      - SERVER_CERT_PEM=/certs/server_cert_localhost.pem  # Server public key
      - SERVER_CERT_KEY=/certs/server_key_localhost.pem  # Server private key
      - CLIENT_CERT_PEM=/certs/client_cert_localhost.pem  # Client public key
      # Keep the rest unchanged
```

and the ensure the `./scripts/oqs_env.sh` script is set to use the same certificates when `QKD_BACKEND=python_client` is set in the `QUBIP_DIR` variable.

Then

```bash
# 1) Prepare environment for OpenSSL and the provider in each terminal
export QKD_BACKEND=python_client
source ./scripts/oqs_env.sh
export IS_TLS_SERVER=1 # In the server terminal
export LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libpython3.10.so.1.0
```

### TLS integration tests

You can test the QKD-KEM groups for TLS in the following way.

First, generate certificates (you need to have installed OpenSSL 3.0 and the oqs-provider as explained before)

```bash
cd ./certs
source ./set_env.sh
./generate_certs.sh
```

Next, use `./scripts/oqs_env.sh` to set the environment variables to use the built OpenSSL and the QKD-KEM provider library that we have built under `_build/lib`. You have to set these variables in two different terminals.

Then, in one terminal run the server

```bash
source ./scripts/oqs_env.sh
export IS_TLS_SERVER=1
openssl s_server -cert <certs_dir>/rsa/rsa_2048_entity_cert.pem -key <certs_dir>/rsa/rsa_2048_entity_key.pem -www -tls1_3 -groups qkd_kyber768 -port 4433 -provider default -provider qkdkemprovider
```

and in the other terminal run the client

```bash
source ./scripts/oqs_env.sh
openssl s_client -connect localhost:4433 -groups qkd_kyber768 -provider default -provider qkdkemprovider
```

**Note**: the `IS_TLS_SERVER` variable is used to set the server mode (this is meant to avoid an unnecesary `get_key` call in the server side for ETSI 014 and `QKD_KEY_ID_CH=ON`).

Notice that Wireshark won't be able to recognize the groups, so you will see

```text
Supported Groups (1 group)
 Supported Group: Unknown (0x303c)
```

## Automated with Python

You can also run the following script

```bash
python3 ./scripts/test_qkd_kem_tls.py
```

which is based in [open-quantum-safe/oqs-provider/scripts/test_tls_full.py](https://github.com/open-quantum-safe/oqs-provider/blob/main/scripts/test_tls_full.py) and will run the server and the client automatically.

## Configuring the QuKayDee environment

First, follow the instructions in the [QuKayDee](https://qukaydee.com/pages/getting_started) page. At some point, you will have to download the server's certificate. This will have a name of the form

```bash
account-<ACCOUNT_ID>-server-ca-qukaydee-com.crt
```

Use this ACCOUNT_ID number for configuring your environment. When you have configured the rest of the certificates (do not forget to upload the client's root certificate to the site), save them to a folder called ```qkd_certs``` in the root's directory. You can then configure the environment by running

```bash
export QKD_BACKEND=qukaydee && export ACCOUNT_ID="<ACCOUNT_ID>"
source ./scripts/oqs_env.sh
```
