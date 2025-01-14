// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL common provider capabilities.
 *
 * ToDo: Interop testing.
 */

#include <assert.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <string.h>

/* For TLS1_VERSION etc */
#include <openssl/params.h>
#include <openssl/ssl.h>

// internal, but useful OSSL define:
#define OSSL_NELEM(x) (sizeof(x) / sizeof((x)[0]))

#include "oqs_prov.h"

typedef struct oqs_group_constants_st {
    unsigned int group_id; /* Group ID */
    unsigned int secbits;  /* Bits of security */
    int mintls;            /* Minimum TLS version, -1 unsupported */
    int maxtls;            /* Maximum TLS version (or 0 for undefined) */
    int mindtls;           /* Minimum DTLS version, -1 unsupported */
    int maxdtls;           /* Maximum DTLS version (or 0 for undefined) */
    int is_kem;            /* Always set */
} OQS_GROUP_CONSTANTS;

static OQS_GROUP_CONSTANTS oqs_group_list[] = {
    // TODO_QKD: check the codes
    {0x3000, 128, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_frodo640aes
    {0x3001, 128, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_frodo640shake
    {0x3002, 192, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_frodo976aes
    {0x3003, 192, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_frodo976shake
    {0x3004, 256, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_frodo1344aes
    {0x3005, 256, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_frodo1344shake
    {0x303A, 128, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_kyber512
    {0x303C, 192, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_kyber768
    {0x303D, 256, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_kyber1024
    {0x304A, 128, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_mlkem512
    {0x3768, 192, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_mlkem768
    {0x3024, 256, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_mlkem1024
    {0x3041, 128, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_bikel1
    {0x3042, 192, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_bikel3
    {0x3043, 256, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_bikel5
    {0x3044, 128, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_hqc128
    {0x3045, 192, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_hqc192
    {0x3046, 256, TLS1_3_VERSION, 0, -1, -1, 1}, // qkd_hqc256
};

// Adds entries for tlsname, `ecx`_tlsname and `ecp`_tlsname
#define OQS_GROUP_ENTRY(tlsname, realname, algorithm, idx)                     \
    {                                                                          \
        OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, #tlsname,       \
                               sizeof(#tlsname)),                              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL,    \
                                   #realname, sizeof(#realname)),              \
            OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, #algorithm,  \
                                   sizeof(#algorithm)),                        \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID,                      \
                            (unsigned int *)&oqs_group_list[idx].group_id),    \
            OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS,           \
                            (unsigned int *)&oqs_group_list[idx].secbits),     \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,                  \
                           (unsigned int *)&oqs_group_list[idx].mintls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,                  \
                           (unsigned int *)&oqs_group_list[idx].maxtls),       \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,                 \
                           (unsigned int *)&oqs_group_list[idx].mindtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,                 \
                           (unsigned int *)&oqs_group_list[idx].maxdtls),      \
            OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,                   \
                           (unsigned int *)&oqs_group_list[idx].is_kem),       \
            OSSL_PARAM_END                                                     \
    }

static const OSSL_PARAM oqs_param_group_list[][11] = {
///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_START

#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    OQS_GROUP_ENTRY(qkd_frodo640aes, qkd_frodo640aes, qkd_frodo640aes, 1),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    OQS_GROUP_ENTRY(qkd_frodo640shake, qkd_frodo640shake, qkd_frodo640shake, 2),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    OQS_GROUP_ENTRY(qkd_frodo976aes, qkd_frodo976aes, qkd_frodo976aes, 3),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    OQS_GROUP_ENTRY(qkd_frodo976shake, qkd_frodo976shake, qkd_frodo976shake,
                    4),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    OQS_GROUP_ENTRY(qkd_frodo1344aes, qkd_frodo1344aes, qkd_frodo1344aes, 5),
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    OQS_GROUP_ENTRY(qkd_frodo1344shake, qkd_frodo1344shake, qkd_frodo1344shake,
                    6),
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    OQS_GROUP_ENTRY(qkd_kyber512, qkd_kyber512, qkd_kyber512, 7),
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    OQS_GROUP_ENTRY(qkd_kyber768, qkd_kyber768, qkd_kyber768, 8),
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    OQS_GROUP_ENTRY(qkd_kyber1024, qkd_kyber1024, qkd_kyber1024, 9),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
    OQS_GROUP_ENTRY(qkd_mlkem512, qkd_mlkem512, qkd_mlkem512, 10),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    OQS_GROUP_ENTRY(qkd_mlkem768, qkd_mlkem768, qkd_mlkem768, 11),
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    OQS_GROUP_ENTRY(qkd_mlkem1024, qkd_mlkem1024, qkd_mlkem1024, 12),
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    OQS_GROUP_ENTRY(qkd_bikel1, qkd_bikel1, qkd_bikel1, 13),
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    OQS_GROUP_ENTRY(qkd_bikel3, qkd_bikel3, qkd_bikel3, 14),
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    OQS_GROUP_ENTRY(qkd_bikel5, qkd_bikel5, qkd_bikel5, 15),
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    OQS_GROUP_ENTRY(qkd_hqc128, qkd_hqc128, qkd_hqc128, 16),
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    OQS_GROUP_ENTRY(qkd_hqc192, qkd_hqc192, qkd_hqc192, 17),
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    OQS_GROUP_ENTRY(qkd_hqc256, qkd_hqc256, qkd_hqc256, 18),
#endif
    ///// OQS_TEMPLATE_FRAGMENT_GROUP_NAMES_END
};

int oqs_patch_codepoints() {
    if (getenv("OQS_CODEPOINT_QKD_FRODO640AES"))
        oqs_group_list[1].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_FRODO640AES"));
    if (getenv("OQS_CODEPOINT_QKD_FRODO640SHAKE"))
        oqs_group_list[2].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_FRODO640SHAKE"));
    if (getenv("OQS_CODEPOINT_QKD_FRODO976AES"))
        oqs_group_list[3].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_FRODO976AES"));
    if (getenv("OQS_CODEPOINT_QKD_FRODO976SHAKE"))
        oqs_group_list[4].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_FRODO976SHAKE"));
    if (getenv("OQS_CODEPOINT_QKD_FRODO1344AES"))
        oqs_group_list[5].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_FRODO1344AES"));
    if (getenv("OQS_CODEPOINT_QKD_FRODO1344SHAKE"))
        oqs_group_list[6].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_FRODO1344SHAKE"));
    if (getenv("OQS_CODEPOINT_QKD_KYBER512"))
        oqs_group_list[7].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_KYBER512"));
    if (getenv("OQS_CODEPOINT_QKD_KYBER768"))
        oqs_group_list[8].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_KYBER768"));
    if (getenv("OQS_CODEPOINT_QKD_KYBER1024"))
        oqs_group_list[9].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_KYBER1024"));
    if (getenv("OQS_CODEPOINT_QKD_MLKEM512"))
        oqs_group_list[10].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_MLKEM512"));
    if (getenv("OQS_CODEPOINT_QKD_MLKEM768"))
        oqs_group_list[11].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_MLKEM768"));
    if (getenv("OQS_CODEPOINT_QKD_MLKEM1024"))
        oqs_group_list[12].group_id =
            atoi(getenv("OQS_CODEPOINT_QKD_MLKEM1024"));
    if (getenv("OQS_CODEPOINT_QKD_BIKEL1"))
        oqs_group_list[13].group_id = atoi(getenv("OQS_CODEPOINT_QKD_BIKEL1"));
    if (getenv("OQS_CODEPOINT_QKD_BIKEL3"))
        oqs_group_list[14].group_id = atoi(getenv("OQS_CODEPOINT_QKD_BIKEL3"));
    if (getenv("OQS_CODEPOINT_QKD_BIKEL5"))
        oqs_group_list[15].group_id = atoi(getenv("OQS_CODEPOINT_QKD_BIKEL5"));
    if (getenv("OQS_CODEPOINT_QKD_HQC128"))
        oqs_group_list[16].group_id = atoi(getenv("OQS_CODEPOINT_QKD_HQC128"));
    if (getenv("OQS_CODEPOINT_QKD_HQC192"))
        oqs_group_list[17].group_id = atoi(getenv("OQS_CODEPOINT_QKD_HQC192"));
    if (getenv("OQS_CODEPOINT_QKD_HQC256"))
        oqs_group_list[18].group_id = atoi(getenv("OQS_CODEPOINT_QKD_HQC256"));

    return 1;
}

static int oqs_group_capability(OSSL_CALLBACK *cb, void *arg) {
    size_t i;

    for (i = 0; i < OSSL_NELEM(oqs_param_group_list); i++) {
        if (!cb(oqs_param_group_list[i], arg))
            return 0;
    }

    return 1;
}

int oqs_provider_get_capabilities(void *provctx, const char *capability,
                                  OSSL_CALLBACK *cb, void *arg) {
    if (strcasecmp(capability, "TLS-GROUP") == 0)
        return oqs_group_capability(cb, arg);

    /* We don't support this capability */
    return 0;
}
