// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider encoders
 *
 * Code strongly inspired by OpenSSL default provider.
 *
 */

#ifndef ENCODER_PROVIDER
#    error Macro ENCODER_PROVIDER undefined
#endif

#define ENCODER_STRUCTURE_type_specific_keypair   "type-specific"
#define ENCODER_STRUCTURE_type_specific_params    "type-specific"
#define ENCODER_STRUCTURE_type_specific           "type-specific"
#define ENCODER_STRUCTURE_type_specific_no_pub    "type-specific"
#define ENCODER_STRUCTURE_PKCS8                   "pkcs8"
#define ENCODER_STRUCTURE_SubjectPublicKeyInfo    "SubjectPublicKeyInfo"
#define ENCODER_STRUCTURE_PrivateKeyInfo          "PrivateKeyInfo"
#define ENCODER_STRUCTURE_EncryptedPrivateKeyInfo "EncryptedPrivateKeyInfo"
#define ENCODER_STRUCTURE_PKCS1                   "pkcs1"
#define ENCODER_STRUCTURE_PKCS3                   "pkcs3"

/* Arguments are prefixed with '_' to avoid build breaks on certain platforms */
#define ENCODER_TEXT(_name, _sym)                           \
    {                                                       \
        _name, "provider=" ENCODER_PROVIDER ",output=text", \
            (oqs_##_sym##_to_text_encoder_functions)        \
    }
#define ENCODER(_name, _sym, _fips, _output)                     \
    {                                                            \
        _name, "provider=" ENCODER_PROVIDER ",output=" #_output, \
            (oqs_##_sym##_to_##_output##_encoder_functions)      \
    }

#define ENCODER_w_structure(_name, _sym, _output, _structure)              \
    {                                                                      \
        _name,                                                             \
            "provider=" ENCODER_PROVIDER ",output=" #_output               \
            ",structure=" ENCODER_STRUCTURE_##_structure,                  \
            (oqs_##_sym##_to_##_structure##_##_output##_encoder_functions) \
    }

/*
 * Entries for human text "encoders"
 */

/*
 * Entries for key type specific output formats.  The structure name on these
 * is the same as the key type name.  This allows us to say something like:
 *
 * To replace i2d_{TYPE}PrivateKey(), i2d_{TYPE}PublicKey() and
 * i2d_{TYPE}Params(), use OSSL_ENCODER functions with an OSSL_ENCODER_CTX
 * created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "DER", "type-specific",
 *                                   NULL, NULL);
 *
 * To replace PEM_write_bio_{TYPE}PrivateKey(), PEM_write_bio_{TYPE}PublicKey()
 * and PEM_write_bio_{TYPE}Params(), use OSSL_ENCODER functions with an
 * OSSL_ENCODER_CTX created like this:
 *
 * OSSL_ENCODER_CTX *ctx =
 *     OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, "PEM", "type-specific",
 *                                   NULL, NULL);
 *
 * We only implement those for which there are current i2d_ and PEM_write_bio
 * implementations.
 */

/*
 * Entries for PKCS#8 and SubjectPublicKeyInfo.
 * The "der" ones are added convenience for any user that wants to use
 * OSSL_ENCODER directly.
 * The "pem" ones also support PEM_write_bio_PrivateKey() and
 * PEM_write_bio_PUBKEY().
 */

///// OQS_TEMPLATE_FRAGMENT_MAKE_START
#ifdef OQS_KEM_ENCODERS


#ifdef OQS_ENABLE_KEM_frodokem_640_aes
ENCODER_w_structure("qkd_frodo640aes", qkd_frodo640aes, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640aes", qkd_frodo640aes, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640aes", qkd_frodo640aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640aes", qkd_frodo640aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640aes", qkd_frodo640aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_frodo640aes", qkd_frodo640aes, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_frodo640aes", qkd_frodo640aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
ENCODER_w_structure("qkd_frodo640shake", qkd_frodo640shake, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640shake", qkd_frodo640shake, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640shake", qkd_frodo640shake, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640shake", qkd_frodo640shake, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo640shake", qkd_frodo640shake, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_frodo640shake", qkd_frodo640shake, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_frodo640shake", qkd_frodo640shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
ENCODER_w_structure("qkd_frodo976aes", qkd_frodo976aes, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976aes", qkd_frodo976aes, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976aes", qkd_frodo976aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976aes", qkd_frodo976aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976aes", qkd_frodo976aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_frodo976aes", qkd_frodo976aes, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_frodo976aes", qkd_frodo976aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
ENCODER_w_structure("qkd_frodo976shake", qkd_frodo976shake, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976shake", qkd_frodo976shake, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976shake", qkd_frodo976shake, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976shake", qkd_frodo976shake, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo976shake", qkd_frodo976shake, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_frodo976shake", qkd_frodo976shake, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_frodo976shake", qkd_frodo976shake),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
ENCODER_w_structure("qkd_frodo1344aes", qkd_frodo1344aes, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344aes", qkd_frodo1344aes, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344aes", qkd_frodo1344aes, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344aes", qkd_frodo1344aes, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344aes", qkd_frodo1344aes, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_frodo1344aes", qkd_frodo1344aes, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_frodo1344aes", qkd_frodo1344aes),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
ENCODER_w_structure("qkd_frodo1344shake", qkd_frodo1344shake, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344shake", qkd_frodo1344shake, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344shake", qkd_frodo1344shake, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344shake", qkd_frodo1344shake, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_frodo1344shake", qkd_frodo1344shake, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_frodo1344shake", qkd_frodo1344shake, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_frodo1344shake", qkd_frodo1344shake),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
ENCODER_w_structure("qkd_kyber512", qkd_kyber512, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_kyber512", qkd_kyber512, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_kyber512", qkd_kyber512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_kyber512", qkd_kyber512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_kyber512", qkd_kyber512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_kyber512", qkd_kyber512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_kyber512", qkd_kyber512),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
ENCODER_w_structure("qkd_kyber768", qkd_kyber768, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_kyber768", qkd_kyber768, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_kyber768", qkd_kyber768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_kyber768", qkd_kyber768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_kyber768", qkd_kyber768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_kyber768", qkd_kyber768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_kyber768", qkd_kyber768),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
ENCODER_w_structure("qkd_kyber1024", qkd_kyber1024, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_kyber1024", qkd_kyber1024, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_kyber1024", qkd_kyber1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_kyber1024", qkd_kyber1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_kyber1024", qkd_kyber1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_kyber1024", qkd_kyber1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_kyber1024", qkd_kyber1024),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
ENCODER_w_structure("qkd_mlkem512", qkd_mlkem512, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem512", qkd_mlkem512, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem512", qkd_mlkem512, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem512", qkd_mlkem512, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem512", qkd_mlkem512, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_mlkem512", qkd_mlkem512, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_mlkem512", qkd_mlkem512),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
ENCODER_w_structure("qkd_mlkem768", qkd_mlkem768, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem768", qkd_mlkem768, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem768", qkd_mlkem768, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem768", qkd_mlkem768, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem768", qkd_mlkem768, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_mlkem768", qkd_mlkem768, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_mlkem768", qkd_mlkem768),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024,
ENCODER_w_structure("qkd_mlkem1024", qkd_mlkem1024, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem1024", qkd_mlkem1024, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem1024", qkd_mlkem1024, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem1024", qkd_mlkem1024, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_mlkem1024", qkd_mlkem1024, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_mlkem1024", qkd_mlkem1024, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_mlkem1024", qkd_mlkem1024),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
ENCODER_w_structure("qkd_bikel1", qkd_bikel1, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_bikel1", qkd_bikel1, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_bikel1", qkd_bikel1, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_bikel1", qkd_bikel1, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_bikel1", qkd_bikel1, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_bikel1", qkd_bikel1, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_bikel1", qkd_bikel1),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
ENCODER_w_structure("qkd_bikel3", qkd_bikel3, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_bikel3", qkd_bikel3, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_bikel3", qkd_bikel3, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_bikel3", qkd_bikel3, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_bikel3", qkd_bikel3, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_bikel3", qkd_bikel3, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_bikel3", qkd_bikel3),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
ENCODER_w_structure("qkd_bikel5", qkd_bikel5, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_bikel5", qkd_bikel5, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_bikel5", qkd_bikel5, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_bikel5", qkd_bikel5, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_bikel5", qkd_bikel5, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_bikel5", qkd_bikel5, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_bikel5", qkd_bikel5),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
ENCODER_w_structure("qkd_hqc128", qkd_hqc128, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_hqc128", qkd_hqc128, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_hqc128", qkd_hqc128, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_hqc128", qkd_hqc128, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_hqc128", qkd_hqc128, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_hqc128", qkd_hqc128, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_hqc128", qkd_hqc128),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
ENCODER_w_structure("qkd_hqc192", qkd_hqc192, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_hqc192", qkd_hqc192, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_hqc192", qkd_hqc192, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_hqc192", qkd_hqc192, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_hqc192", qkd_hqc192, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_hqc192", qkd_hqc192, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_hqc192", qkd_hqc192),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
ENCODER_w_structure("qkd_hqc256", qkd_hqc256, der, PrivateKeyInfo),
ENCODER_w_structure("qkd_hqc256", qkd_hqc256, pem, PrivateKeyInfo),
ENCODER_w_structure("qkd_hqc256", qkd_hqc256, der, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_hqc256", qkd_hqc256, pem, EncryptedPrivateKeyInfo),
ENCODER_w_structure("qkd_hqc256", qkd_hqc256, der, SubjectPublicKeyInfo),
ENCODER_w_structure("qkd_hqc256", qkd_hqc256, pem, SubjectPublicKeyInfo),
ENCODER_TEXT("qkd_hqc256", qkd_hqc256),
#endif

#endif /* OQS_KEM_ENCODERS */
///// OQS_TEMPLATE_FRAGMENT_MAKE_END
