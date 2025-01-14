// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider decoders
 *
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef DECODER_PROVIDER
#    error Macro DECODER_PROVIDER undefined
#endif

#define DECODER_STRUCTURE_type_specific_keypair "type-specific"
#define DECODER_STRUCTURE_type_specific_params  "type-specific"
#define DECODER_STRUCTURE_type_specific         "type-specific"
#define DECODER_STRUCTURE_type_specific_no_pub  "type-specific"
#define DECODER_STRUCTURE_PKCS8                 "pkcs8"
#define DECODER_STRUCTURE_SubjectPublicKeyInfo  "SubjectPublicKeyInfo"
#define DECODER_STRUCTURE_PrivateKeyInfo        "PrivateKeyInfo"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define DECODER(_name, _input, _output)                        \
    {                                                          \
        _name, "provider=" DECODER_PROVIDER ",input=" #_input, \
            (oqs_##_input##_to_##_output##_decoder_functions)  \
    }
#define DECODER_w_structure(_name, _input, _structure, _output)              \
    {                                                                        \
        _name,                                                               \
            "provider=" DECODER_PROVIDER ",input=" #_input                   \
            ",structure=" DECODER_STRUCTURE_##_structure,                    \
            (oqs_##_structure##_##_input##_to_##_output##_decoder_functions) \
    }

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
#ifdef OQS_KEM_ENCODERS

#ifdef OQS_ENABLE_KEM_frodokem_640_aes
DECODER_w_structure("qkd_frodo640aes", der, PrivateKeyInfo, p256_frodo640aes),
DECODER_w_structure("qkd_frodo640aes", der, SubjectPublicKeyInfo, p256_frodo640aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
DECODER_w_structure("qkd_frodo640shake", der, PrivateKeyInfo, p256_frodo640shake),
DECODER_w_structure("qkd_frodo640shake", der, SubjectPublicKeyInfo, p256_frodo640shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
DECODER_w_structure("qkd_frodo976aes", der, PrivateKeyInfo, p384_frodo976aes),
DECODER_w_structure("qkd_frodo976aes", der, SubjectPublicKeyInfo, p384_frodo976aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
DECODER_w_structure("qkd_frodo976shake", der, PrivateKeyInfo, p384_frodo976shake),
DECODER_w_structure("qkd_frodo976shake", der, SubjectPublicKeyInfo, p384_frodo976shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
DECODER_w_structure("qkd_frodo1344aes", der, PrivateKeyInfo, p521_frodo1344aes),
DECODER_w_structure("qkd_frodo1344aes", der, SubjectPublicKeyInfo, p521_frodo1344aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
DECODER_w_structure("qkd_frodo1344shake", der, PrivateKeyInfo, p521_frodo1344shake),
DECODER_w_structure("qkd_frodo1344shake", der, SubjectPublicKeyInfo, p521_frodo1344shake),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
DECODER_w_structure("qkd_kyber512", der, PrivateKeyInfo, p256_kyber512),
DECODER_w_structure("qkd_kyber512", der, SubjectPublicKeyInfo, p256_kyber512),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
DECODER_w_structure("qkd_kyber768", der, PrivateKeyInfo, p384_kyber768),
DECODER_w_structure("qkd_kyber768", der, SubjectPublicKeyInfo, p384_kyber768),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
DECODER_w_structure("qkd_kyber1024", der, PrivateKeyInfo, p521_kyber1024),
DECODER_w_structure("qkd_kyber1024", der, SubjectPublicKeyInfo, p521_kyber1024),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
DECODER_w_structure("qkd_mlkem512", der, PrivateKeyInfo, p256_mlkem512),
DECODER_w_structure("qkd_mlkem512", der, SubjectPublicKeyInfo, p256_mlkem512),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
DECODER_w_structure("qkd_mlkem768", der, PrivateKeyInfo, p384_mlkem768),
DECODER_w_structure("qkd_mlkem768", der, SubjectPublicKeyInfo, p384_mlkem768),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
DECODER_w_structure("qkd_mlkem1024", der, PrivateKeyInfo, p521_mlkem1024),
DECODER_w_structure("qkd_mlkem1024", der, SubjectPublicKeyInfo, p521_mlkem1024),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
DECODER_w_structure("qkd_bikel1", der, PrivateKeyInfo, p256_bikel1),
DECODER_w_structure("qkd_bikel1", der, SubjectPublicKeyInfo, p256_bikel1),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
DECODER_w_structure("qkd_bikel3", der, PrivateKeyInfo, p384_bikel3),
DECODER_w_structure("qkd_bikel3", der, SubjectPublicKeyInfo, p384_bikel3),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
DECODER_w_structure("qkd_bikel5", der, PrivateKeyInfo, p521_bikel5),
DECODER_w_structure("qkd_bikel5", der, SubjectPublicKeyInfo, p521_bikel5),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
DECODER_w_structure("qkd_hqc128", der, PrivateKeyInfo, p256_hqc128),
DECODER_w_structure("qkd_hqc128", der, SubjectPublicKeyInfo, p256_hqc128),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
DECODER_w_structure("qkd_hqc192", der, PrivateKeyInfo, p384_hqc192),
DECODER_w_structure("qkd_hqc192", der, SubjectPublicKeyInfo, p384_hqc192),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
DECODER_w_structure("qkd_hqc256", der, PrivateKeyInfo, p521_hqc256),
DECODER_w_structure("qkd_hqc256", der, SubjectPublicKeyInfo, p521_hqc256),
#endif

#endif /* OQS_KEM_ENCODERS */

///// OQS_TEMPLATE_FRAGMENT_MAKE_END
