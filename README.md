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
cmake -DQKD_BACKEND=simulated -DQKD_DEBUG_LEVEL=4 -DBUILD_TESTS=ON ..
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

## Running KEM tests

To run the KEM tests, use the following command:

```bash
./test_kems.sh
```