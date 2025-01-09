#!/bin/bash

if [ "$OPENSSL" = "" ]; then
   #OPENSSL=/usr/local/bin/oqs_openssl
   OPENSSL=/usr/local/bin/oqs_openssl3
fi
# add provider path if not defined
if [ "$PROVIDER_PATH" = "" ]; then
   PROVIDER_PATH=/opt/oqs_openssl3/oqs-provider/_build/lib
fi

# Create directory structure
CERT_BASE_DIR="."
DILITHIUM_DIR="${CERT_BASE_DIR}/dilithium"
FALCON_DIR="${CERT_BASE_DIR}/falcon"
RSA_DIR="${CERT_BASE_DIR}/rsa"

mkdir -p ${DILITHIUM_DIR}
mkdir -p ${FALCON_DIR}
mkdir -p ${RSA_DIR}

# Generate conf files.
printf "\
[ req ]\n\
prompt                 = no\n\
distinguished_name     = req_distinguished_name\n\
\n\
[ req_distinguished_name ]\n\
C                      = CA\n\
ST                     = ON\n\
L                      = Waterloo\n\
O                      = wolfSSL Inc.\n\
OU                     = Engineering\n\
CN                     = Root Certificate\n\
emailAddress           = root@wolfssl.com\n\
\n\
[ ca_extensions ]\n\
subjectKeyIdentifier   = hash\n\
authorityKeyIdentifier = keyid:always,issuer:always\n\
keyUsage               = critical, keyCertSign\n\
basicConstraints       = critical, CA:true\n" > root.conf

printf "\
[ req ]\n\
prompt                 = no\n\
distinguished_name     = req_distinguished_name\n\
\n\
[ req_distinguished_name ]\n\
C                      = CA\n\
ST                     = ON\n\
L                      = Waterloo\n\
O                      = wolfSSL Inc.\n\
OU                     = Engineering\n\
CN                     = Entity Certificate\n\
emailAddress           = entity@wolfssl.com\n\
\n\
[ x509v3_extensions ]\n\
subjectAltName = IP:127.0.0.1\n\
subjectKeyIdentifier   = hash\n\
authorityKeyIdentifier = keyid:always,issuer:always\n\
keyUsage               = critical, digitalSignature\n\
extendedKeyUsage       = critical, serverAuth,clientAuth\n\
basicConstraints       = critical, CA:false\n" > entity.conf

###############################################################################
# Dilithium2
###############################################################################

echo "Generating DILITHIUM2 keys..."
${OPENSSL} genpkey -algorithm dilithium2 -outform pem -out ${DILITHIUM_DIR}/dilithium2_root_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default
${OPENSSL} genpkey -algorithm dilithium2 -outform pem -out ${DILITHIUM_DIR}/dilithium2_entity_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM2 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 256 -key ${DILITHIUM_DIR}/dilithium2_root_key.pem -out ${DILITHIUM_DIR}/dilithium2_root_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM2 entity CSR..."
${OPENSSL} req -new -config entity.conf -key ${DILITHIUM_DIR}/dilithium2_entity_key.pem -out ${DILITHIUM_DIR}/dilithium2_entity_req.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM2 entity certificate..."
${OPENSSL} x509 -req -in ${DILITHIUM_DIR}/dilithium2_entity_req.pem -CA ${DILITHIUM_DIR}/dilithium2_root_cert.pem -CAkey ${DILITHIUM_DIR}/dilithium2_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 257 -out ${DILITHIUM_DIR}/dilithium2_entity_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

###############################################################################
# Dilithium3
###############################################################################

echo "Generating DILITHIUM3 keys..."
${OPENSSL} genpkey -algorithm dilithium3 -outform pem -out ${DILITHIUM_DIR}/dilithium3_root_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default
${OPENSSL} genpkey -algorithm dilithium3 -outform pem -out ${DILITHIUM_DIR}/dilithium3_entity_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM3 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 512 -key ${DILITHIUM_DIR}/dilithium3_root_key.pem -out ${DILITHIUM_DIR}/dilithium3_root_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM3 entity CSR..."
${OPENSSL} req -new -config entity.conf -key ${DILITHIUM_DIR}/dilithium3_entity_key.pem -out ${DILITHIUM_DIR}/dilithium3_entity_req.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM3 entity certificate..."
${OPENSSL} x509 -req -in ${DILITHIUM_DIR}/dilithium3_entity_req.pem -CA ${DILITHIUM_DIR}/dilithium3_root_cert.pem -CAkey ${DILITHIUM_DIR}/dilithium3_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 513 -out ${DILITHIUM_DIR}/dilithium3_entity_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

###############################################################################
# Dilithium5
###############################################################################

echo "Generating DILITHIUM5 keys..."
${OPENSSL} genpkey -algorithm dilithium5 -outform pem -out ${DILITHIUM_DIR}/dilithium5_root_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default
${OPENSSL} genpkey -algorithm dilithium5 -outform pem -out ${DILITHIUM_DIR}/dilithium5_entity_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM5 Level 5 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 1024 -key ${DILITHIUM_DIR}/dilithium5_root_key.pem -out ${DILITHIUM_DIR}/dilithium5_root_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM5 Level 5 entity CSR..."
${OPENSSL} req -new -config entity.conf -key ${DILITHIUM_DIR}/dilithium5_entity_key.pem -out ${DILITHIUM_DIR}/dilithium5_entity_req.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating DILITHIUM5 Level 5 entity certificate..."
${OPENSSL} x509 -req -in ${DILITHIUM_DIR}/dilithium5_entity_req.pem -CA ${DILITHIUM_DIR}/dilithium5_root_cert.pem -CAkey ${DILITHIUM_DIR}/dilithium5_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 1025 -out ${DILITHIUM_DIR}/dilithium5_entity_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

###############################################################################
# Falcon NIST Level 1
###############################################################################

echo "Generating Falcon NIST Level 1 keys..."
${OPENSSL} genpkey -algorithm falcon512 -outform pem -out ${FALCON_DIR}/falcon_level1_root_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default
${OPENSSL} genpkey -algorithm falcon512 -outform pem -out ${FALCON_DIR}/falcon_level1_entity_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating Falcon NIST Level 1 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 512 -key ${FALCON_DIR}/falcon_level1_root_key.pem -out ${FALCON_DIR}/falcon_level1_root_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating Falcon NIST Level 1 entity CSR..."
${OPENSSL} req -new -config entity.conf -key ${FALCON_DIR}/falcon_level1_entity_key.pem -out ${FALCON_DIR}/falcon_level1_entity_req.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating Falcon NIST Level 1 entity certificate..."
${OPENSSL} x509 -req -in ${FALCON_DIR}/falcon_level1_entity_req.pem -CA ${FALCON_DIR}/falcon_level1_root_cert.pem -CAkey ${FALCON_DIR}/falcon_level1_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 513 -out ${FALCON_DIR}/falcon_level1_entity_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

###############################################################################
# Falcon NIST Level 5
###############################################################################

echo "Generating Falcon NIST Level 5 keys..."
${OPENSSL} genpkey -algorithm falcon1024 -outform pem -out ${FALCON_DIR}/falcon_level5_root_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default
${OPENSSL} genpkey -algorithm falcon1024 -outform pem -out ${FALCON_DIR}/falcon_level5_entity_key.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating Falcon NIST Level 5 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 1024 -key ${FALCON_DIR}/falcon_level5_root_key.pem -out ${FALCON_DIR}/falcon_level5_root_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating Falcon NIST Level 5 entity CSR..."
${OPENSSL} req -new -config entity.conf -key ${FALCON_DIR}/falcon_level5_entity_key.pem -out ${FALCON_DIR}/falcon_level5_entity_req.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

echo "Generating Falcon NIST Level 5 entity certificate..."
${OPENSSL} x509 -req -in ${FALCON_DIR}/falcon_level5_entity_req.pem -CA ${FALCON_DIR}/falcon_level5_root_cert.pem -CAkey ${FALCON_DIR}/falcon_level5_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 1025 -out ${FALCON_DIR}/falcon_level5_entity_cert.pem -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default

###############################################################################
# RSA 2048
###############################################################################

echo "Generating RSA 2048 keys..."
${OPENSSL} genpkey -algorithm RSA -out ${RSA_DIR}/rsa_2048_root_key.pem
${OPENSSL} genpkey -algorithm RSA -out ${RSA_DIR}/rsa_2048_entity_key.pem

echo "Generating RSA 2048 root certificate..."
${OPENSSL} req -x509 -config root.conf -extensions ca_extensions -days 1095 -set_serial 512 -key ${RSA_DIR}/rsa_2048_root_key.pem -out ${RSA_DIR}/rsa_2048_root_cert.pem

echo "Generating RSA 2048 entity CSR..."
${OPENSSL} req -new -config entity.conf -key ${RSA_DIR}/rsa_2048_entity_key.pem -out ${RSA_DIR}/rsa_2048_entity_req.pem

echo "Generating RSA 2048 entity certificate..."
${OPENSSL} x509 -req -in ${RSA_DIR}/rsa_2048_entity_req.pem -CA ${RSA_DIR}/rsa_2048_root_cert.pem -CAkey ${RSA_DIR}/rsa_2048_root_key.pem -extfile entity.conf -extensions x509v3_extensions -days 1095 -set_serial 513 -out ${RSA_DIR}/rsa_2048_entity_cert.pem

###############################################################################
# Verify all generated certificates.
###############################################################################
echo "Verifying certificates..."
${OPENSSL} verify -no-CApath -check_ss_sig -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default -CAfile ${DILITHIUM_DIR}/dilithium3_root_cert.pem ${DILITHIUM_DIR}/dilithium3_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default -CAfile ${FALCON_DIR}/falcon_level1_root_cert.pem ${FALCON_DIR}/falcon_level1_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -provider-path ${PROVIDER_PATH} -provider oqsprovider -provider default -CAfile ${FALCON_DIR}/falcon_level5_root_cert.pem ${FALCON_DIR}/falcon_level5_entity_cert.pem
${OPENSSL} verify -no-CApath -check_ss_sig -CAfile ${RSA_DIR}/rsa_2048_root_cert.pem ${RSA_DIR}/rsa_2048_entity_cert.pem

# Cleanup temporary config files
rm -f root.conf entity.conf