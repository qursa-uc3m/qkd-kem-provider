# QKD-KEM Provider

This fork implements hybrid key encapsulation mechanisms combining quantum key distribution (QKD) with post-quantum cryptography in OpenSSL 3.0. The implementation extends the [oqs-provider](https://github.com/open-quantum-safe/oqs-provider) to enable concurrent use of QKD-derived keys alongside post-quantum KEM operations.

For build instructions and usage details, see the oqs-provider [0.7.0 README](https://github.com/open-quantum-safe/oqs-provider/blob/0.7.0/README.md).

## About the Project

This work is part of the QURSA (Quantum-based Resistant Architectures and Techniques) project, developed through collaboration between:

- Information and Computing Laboratory (I&CLab), Department of Telematic Engineering, Universidade de Vigo (UVigo)
- Pervasive Computing Laboratory, Department of Telematic Engineering, Universidad Carlos III de Madrid (UC3M)

## Dependencies

This project requires our [QKD ETSI API](https://github.com/qursa-uc3m/qkd-etsi-api) implementation, which provides the interface for quantum key distribution operations according to ETSI standards.

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

## Installing the QKD-KEM Provider

Clone the repository and build the project:

```bash
git clone https://github.com/qursa-uc3m/qkd-kem-provider
cd qkd-kem-provider
```

To build the provider for the first time run

```bash
./scripts/fullbuild.sh -F
```

and then just

```bash
./scripts/fullbuild.sh -f
```

## Running the tests

You can run all the tests using the following command:

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

### TLS test

You can test the QKD-KEM groups for TLS in the following way.

First build a OpenSSL (is good to use a clean install to avoid conflicts with your system OpenSSL). You can use the following script to build OpenSSL:

```bash
./scripts/install_openssl3.sh
```

Then you can use the `generate_cert.sh` script to generate the certificates for the server and the client.

Next, use `./scripts/oqs_env.sh` to set the environment variables to use the built OpenSSL and the QKD-KEM provider library that we have built under `_build/lib`. You have to set these variables in two different terminals.

Then, in one terminal run the server

```bash
openssl s_server -cert <certs_dir>/rsa/rsa_2048_entity_cert.pem -key certs/rsa/rsa_2048_entity_key.pem -www -tls1_3 -groups qkd_kyber768 -port 4433 -provider default -provider qkdkemprovider
```

and in the other terminal run the client

```bash
openssl s_client -connect localhost:4433 -groups qkd_kyber768 -provider default -provider qkdkemprovider
```

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
