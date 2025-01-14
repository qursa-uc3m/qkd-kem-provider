// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 key handler.
 *
 * Code strongly inspired by OpenSSL crypto/ec key handler but relocated here
 * to have code within provider.
 *
 */

#include <assert.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <string.h>

#include "oqs_prov.h"
#include "oqs_qkd_ctx.h"

#define DEBUG_QKD

#ifdef NDEBUG
#define OQS_KEY_PRINTF(a)
#define OQS_KEY_PRINTF2(a, b)
#define OQS_KEY_PRINTF3(a, b, c)
#define QKD_DEBUG(fmt, ...)
#else
#define OQS_KEY_PRINTF(a)                                                      \
    if (getenv("OQSKEY"))                                                      \
    printf(a)
#define OQS_KEY_PRINTF2(a, b)                                                  \
    if (getenv("OQSKEY"))                                                      \
    printf(a, b)
#define OQS_KEY_PRINTF3(a, b, c)                                               \
    if (getenv("OQSKEY"))                                                      \
    printf(a, b, c)
#ifdef DEBUG_QKD
#define QKD_DEBUG(fmt, ...)                                                    \
    fprintf(stderr, "QKD DEBUG: %s:%d: " fmt "\n", __func__, __LINE__,         \
            ##__VA_ARGS__)
#else
#define QKD_DEBUG(fmt, ...)
#endif
#endif // NDEBUG

typedef enum { KEY_OP_PUBLIC, KEY_OP_PRIVATE, KEY_OP_KEYGEN } oqsx_key_op_t;

/// NID/name table

typedef struct {
    int nid;
    char *tlsname;
    char *oqsname;
    int keytype;
    int secbits;
    int reverseshare;
} oqs_nid_name_t;

static int oqsx_key_recreate_classickey(OQSX_KEY *key, oqsx_key_op_t op);

///// OQS_TEMPLATE_FRAGMENT_OQSNAMES_START

#define NID_TABLE_LEN 18

// TODO_QKD: check if we need to add QKD keys here
// TODO_QKD: add QKD hybrids
static oqs_nid_name_t nid_names[NID_TABLE_LEN] = {
#ifdef OQS_KEM_ENCODERS //TODO_QKD: check if this variable is needed

    {0, "qkd_frodo640aes", OQS_KEM_alg_frodokem_640_aes, KEY_TYPE_QKD_HYB_KEM, 128, 0},
    {0, "qkd_frodo640shake", OQS_KEM_alg_frodokem_640_shake, KEY_TYPE_QKD_HYB_KEM, 128, 0},
    {0, "qkd_frodo976aes", OQS_KEM_alg_frodokem_976_aes, KEY_TYPE_QKD_HYB_KEM, 192, 0},
    {0, "qkd_frodo976shake", OQS_KEM_alg_frodokem_976_shake, KEY_TYPE_QKD_HYB_KEM, 192, 0},
    {0, "qkd_frodo1344aes", OQS_KEM_alg_frodokem_1344_aes, KEY_TYPE_QKD_HYB_KEM, 256, 0},
    {0, "qkd_frodo1344shake", OQS_KEM_alg_frodokem_1344_shake, KEY_TYPE_QKD_HYB_KEM, 256, 0}, 
    {0, "qkd_kyber512", OQS_KEM_alg_kyber_512, KEY_TYPE_QKD_HYB_KEM, 128, 0},
    {0, "qkd_kyber768", OQS_KEM_alg_kyber_768, KEY_TYPE_QKD_HYB_KEM, 192, 0},
    {0, "qkd_kyber1024", OQS_KEM_alg_kyber_1024, KEY_TYPE_QKD_HYB_KEM, 256, 0},
    {0, "qkd_mlkem512", OQS_KEM_alg_ml_kem_512, KEY_TYPE_QKD_HYB_KEM, 128, 0},
    {0, "qkd_mlkem768", OQS_KEM_alg_ml_kem_768, KEY_TYPE_QKD_HYB_KEM, 192, 0},
    {0, "qkd_mlkem1024", OQS_KEM_alg_ml_kem_1024, KEY_TYPE_QKD_HYB_KEM, 256, 0},
    {0, "qkd_bikel1", OQS_KEM_alg_bike_l1, KEY_TYPE_QKD_HYB_KEM, 128, 0},
    {0, "qkd_bikel3", OQS_KEM_alg_bike_l3, KEY_TYPE_QKD_HYB_KEM, 192, 0},
    {0, "qkd_bikel5", OQS_KEM_alg_bike_l5, KEY_TYPE_QKD_HYB_KEM, 256, 0},
    {0, "qkd_hqc128", OQS_KEM_alg_hqc_128, KEY_TYPE_QKD_HYB_KEM, 128, 0},
    {0, "qkd_hqc192", OQS_KEM_alg_hqc_192, KEY_TYPE_QKD_HYB_KEM, 192, 0},
    {0, "qkd_hqc256", OQS_KEM_alg_hqc_256, KEY_TYPE_QKD_HYB_KEM, 256, 0},

#endif /* OQS_KEM_ENCODERS */
};

int oqs_set_nid(char *tlsname, int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (!strcmp(nid_names[i].tlsname, tlsname)) {
            nid_names[i].nid = nid;
            return 1;
        }
    }
    return 0;
}

static int get_secbits(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].secbits;
    }
    return 0;
}

static int get_reverseshare(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].reverseshare;
    }
    return 0;
}

static int get_keytype(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].keytype;
    }
    return 0;
}

char *get_oqsname_fromtls(char *tlsname) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].keytype == KEY_TYPE_SIG) {
            if (!strcmp(nid_names[i].oqsname, tlsname) ||
                !strcmp(nid_names[i].tlsname, tlsname))
                return nid_names[i].oqsname;
        }
    }
    return 0; // classical
}

char *get_oqsname(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].oqsname;
    }
    return 0;
}

char *get_cmpname(int nid, int index) {
    int i, len;
    char *name, *s;
    if ((i = get_oqsalg_idx(nid)) == -1)
        return NULL;
    s = nid_names[i].tlsname;
    len = strlen(s);
    for (i = 0; i < len; i++) {
        if (s[i] == '_') {
            break;
        }
    }
    switch (index) {
    case 0:
        name = OPENSSL_strndup(s, i);
        break;
    case 1:
        i += 1;
        name = OPENSSL_strndup(s + i, len - i);
        break;
    default:
        name = NULL;
    }

    return name;
}

int get_oqsalg_idx(int nid) {
    int i;
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return i;
    }
    return -1;
}

/* Sets the index of the key components in a comp_privkey or comp_pubkey array
 */
static void oqsx_comp_set_idx(const OQSX_KEY *key, int *idx_classic,
                              int *idx_pq, int *idx_qkd) {
    // TODO_QKD: put in a shared file with oqs_kmgmt.c and oqsprov_keys.c
    int reverse_share = (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                         key->keytype == KEY_TYPE_ECX_HYB_KEM) &&
                        key->reverse_share;
    if (idx_qkd) {
        // QKD is always last
        *idx_qkd = key->numkeys - 1;
    }
    if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
        // In QKD hybrid case
        if (key->numkeys == 2) {
            // PQC + QKD hybrid
            if (idx_classic)
                *idx_classic = -1; // No classical component
            if (idx_pq)
                *idx_pq = 0; // PQ at index 0, QKD at index 1
            // TODO_QKD: implement the triple hybrid case
        } else if (key->numkeys == 3) {
            // Classical + PQC + QKD triple hybrid
            if (reverse_share) {
                // PQ, Classical, QKD order
                if (idx_classic)
                    *idx_classic = 1;
                if (idx_pq)
                    *idx_pq = 0;
            } else {
                // Classical, PQ, QKD order
                if (idx_classic)
                    *idx_classic = 0;
                if (idx_pq)
                    *idx_pq = 1;
            }
        }
    } else {
        // Regular hybrid cases (no QKD)
        if (reverse_share) {
            if (idx_classic)
                *idx_classic = key->numkeys - 1;
            if (idx_pq)
                *idx_pq = 0;
        } else {
            if (idx_classic)
                *idx_classic = 0;
            if (idx_pq)
                *idx_pq = key->numkeys - 1;
        }
        if (idx_qkd)
            *idx_qkd = -1; // No QKD component
    }
}

/* Sets the index of the key components in a comp_privkey or comp_pubkey array
 */
static int oqsx_comp_set_offsets(const OQSX_KEY *key, int set_privkey_offsets,
                                 int set_pubkey_offsets,
                                 int classic_lengths_fixed) {
    int ret = 1;
    uint32_t classic_pubkey_len = 0;
    uint32_t classic_privkey_len = 0;
    char *privkey = (char *)key->privkey;
    char *pubkey = (char *)key->pubkey;

    // The only special case with reversed keys (so far)
    // is: x25519_mlkem*
    int reverse_share = (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                         key->keytype == KEY_TYPE_ECX_HYB_KEM) &&
                        key->reverse_share;

    if (set_privkey_offsets) {
        if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
            if (key->numkeys == 3) {
                // Classic key
                key->comp_privkey[0] = privkey + SIZE_OF_UINT32;
                if (!classic_lengths_fixed) {
                    DECODE_UINT32(classic_privkey_len, privkey);
                    if (classic_privkey_len >
                        key->evp_info->length_private_key) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        ret = 0;
                        goto err;
                    }
                } else {
                    classic_privkey_len = key->evp_info->length_private_key;
                }
                if (reverse_share) {
                    // Structure: UINT32 | PQ_KEY | CLASSIC_KEY | QKD_KEY
                    key->comp_privkey[1] = privkey + SIZE_OF_UINT32 +
                                           key->oqsx_provider_ctx.oqsx_qs_ctx
                                               .kem->length_secret_key;
                    key->comp_privkey[2] = privkey + SIZE_OF_UINT32 +
                                           key->oqsx_provider_ctx.oqsx_qs_ctx
                                               .kem->length_secret_key +
                                           classic_privkey_len;
                } else {
                    // Structure: UINT32 | CLASSIC_KEY | PQ_KEY | QKD_KEY
                    key->comp_privkey[1] =
                        privkey + SIZE_OF_UINT32 + classic_privkey_len;
                    key->comp_privkey[2] = privkey + SIZE_OF_UINT32 +
                                           classic_privkey_len +
                                           key->oqsx_provider_ctx.oqsx_qs_ctx
                                               .kem->length_secret_key;
                }
            } else if (key->numkeys == 2) {
                // Structure: PQ_KEY | QKD_KEY
                key->comp_privkey[0] = privkey;
                key->comp_privkey[1] =
                    privkey +
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
            } else {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                ret = 0;
                goto err;
            }
        } else {
            // Handle non-QKD cases as before
            key->comp_privkey[0] = privkey + SIZE_OF_UINT32;

            if (!classic_lengths_fixed) {
                DECODE_UINT32(classic_privkey_len, privkey);
                if (classic_privkey_len > key->evp_info->length_private_key) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    ret = 0;
                    goto err;
                }
            } else {
                classic_privkey_len = key->evp_info->length_private_key;
            }
            if (reverse_share) {
                // structure is:
                // UINT32 (encoding classic key size) | PQ_KEY | CLASSIC_KEY
                key->comp_privkey[1] =
                    privkey +
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key +
                    SIZE_OF_UINT32;
            } else {
                // structure is:
                // UINT32 (encoding classic key size) | CLASSIC_KEY | PQ_KEY
                key->comp_privkey[1] =
                    privkey + classic_privkey_len + SIZE_OF_UINT32;
            }
        }
    }

    if (set_pubkey_offsets) {
        if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
            if (key->numkeys == 3) {
                // Classic key
                key->comp_pubkey[0] = pubkey + SIZE_OF_UINT32;
                if (!classic_lengths_fixed) {
                    DECODE_UINT32(classic_pubkey_len, pubkey);
                    if (classic_pubkey_len > key->evp_info->length_public_key) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        ret = 0;
                        goto err;
                    }
                } else {
                    classic_pubkey_len = key->evp_info->length_public_key;
                }
                if (reverse_share) {
                    // Structure: UINT32 | PQ_KEY | CLASSIC_KEY | QKD_KEY_ID
                    key->comp_pubkey[1] = pubkey + SIZE_OF_UINT32 +
                                          key->oqsx_provider_ctx.oqsx_qs_ctx
                                              .kem->length_public_key;
                    key->comp_pubkey[2] = pubkey + SIZE_OF_UINT32 +
                                          key->oqsx_provider_ctx.oqsx_qs_ctx
                                              .kem->length_public_key +
                                          classic_pubkey_len;
                } else {
                    // Structure: UINT32 | CLASSIC_KEY | PQ_KEY | QKD_KEY_ID
                    key->comp_pubkey[1] =
                        pubkey + SIZE_OF_UINT32 + classic_pubkey_len;
                    key->comp_pubkey[2] = pubkey + SIZE_OF_UINT32 +
                                          classic_pubkey_len +
                                          key->oqsx_provider_ctx.oqsx_qs_ctx
                                              .kem->length_public_key;
                }
            } else if (key->numkeys == 2) {
                // Structure: PQ_KEY | QKD_KEY_ID
                key->comp_pubkey[0] = pubkey;
                key->comp_pubkey[1] =
                    pubkey +
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
            } else {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                ret = 0;
                goto err;
            }
        } else {
            key->comp_pubkey[0] = pubkey + SIZE_OF_UINT32;

            if (!classic_lengths_fixed) {
                DECODE_UINT32(classic_pubkey_len, pubkey);
                if (classic_pubkey_len > key->evp_info->length_public_key) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    ret = 0;
                    goto err;
                }
            } else {
                classic_pubkey_len = key->evp_info->length_public_key;
            }

            if (reverse_share) {
                // structure is:
                // UINT32 (encoding classic key size) | PQ_KEY | CLASSIC_KEY
                key->comp_pubkey[1] =
                    pubkey +
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key +
                    SIZE_OF_UINT32;
            } else {
                // structure is:
                // UINT32 (encoding classic key size) | CLASSIC_KEY | PQ_KEY
                key->comp_pubkey[1] =
                    pubkey + classic_pubkey_len + SIZE_OF_UINT32;
            }
        }
    }
err:
    return ret;
}

/* Prepare composite data structures. RetVal 0 is error. */
static int oqsx_key_set_composites(OQSX_KEY *key, int classic_lengths_fixed) {
    int ret = 1;

    OQS_KEY_PRINTF2("Setting composites with evp_info %p\n", key->evp_info);

    if (key->numkeys == 1) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0] = key->pubkey;
    } else { // TBD: extend for more than 1 classic key or first OQS for
             // composite:
        if (key->keytype == KEY_TYPE_CMP_SIG) {
            int i;
            int privlen = 0;
            int publen = 0;
            for (i = 0; i < key->numkeys; i++) {
                if (key->privkey) {
                    key->comp_privkey[i] = (char *)key->privkey + privlen;
                    privlen += key->privkeylen_cmp[i];
                } else {
                    key->comp_privkey[i] = NULL;
                }
                if (key->pubkey) {
                    key->comp_pubkey[i] = (char *)key->pubkey + publen;
                    publen += key->pubkeylen_cmp[i];
                } else {
                    key->comp_pubkey[i] = NULL;
                }
            }
        } else {

            /* Sets composites for comp_privkey and comp_pubkey structures, if
             * applicable */
            ret = oqsx_comp_set_offsets(key, key->privkey != NULL,
                                        key->pubkey != NULL,
                                        classic_lengths_fixed);
            ON_ERR_GOTO(ret == 0, err);

            if (!key->privkey) {
                key->comp_privkey[0] = NULL;
                key->comp_privkey[1] = NULL;
                if (key->numkeys == 3) { // triple hybrid with QKD
                    key->comp_privkey[2] = NULL;
                }
            }
            if (!key->pubkey) {
                key->comp_pubkey[0] = NULL;
                key->comp_pubkey[1] = NULL;
                if (key->numkeys == 3) { // triple hybrid with QKD
                    key->comp_pubkey[2] = NULL;
                }
            }
        }
    }
err:
    return ret;
}

PROV_OQS_CTX *oqsx_newprovctx(OSSL_LIB_CTX *libctx,
                              const OSSL_CORE_HANDLE *handle, BIO_METHOD *bm) {
    PROV_OQS_CTX *ret = OPENSSL_zalloc(sizeof(PROV_OQS_CTX));
    if (ret) {
        ret->libctx = libctx;
        ret->handle = handle;
        ret->corebiometh = bm;
    }
    return ret;
}

void oqsx_freeprovctx(PROV_OQS_CTX *ctx) {
    OSSL_LIB_CTX_free(ctx->libctx);
    BIO_meth_free(ctx->corebiometh);
    OPENSSL_free(ctx);
}

void oqsx_key_set0_libctx(OQSX_KEY *key, OSSL_LIB_CTX *libctx) {
    key->libctx = libctx;
}

/* convenience function creating OQSX keys from nids (only for sigs) */
static OQSX_KEY *oqsx_key_new_from_nid(OSSL_LIB_CTX *libctx, const char *propq,
                                       int nid) {
    OQS_KEY_PRINTF2("Generating OQSX key for nid %d\n", nid);

    char *tls_algname = (char *)OBJ_nid2sn(nid);
    OQS_KEY_PRINTF2("                    for tls_name %s\n", tls_algname);

    if (!tls_algname) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return NULL;
    }

    return oqsx_key_new(libctx, get_oqsname(nid), tls_algname, get_keytype(nid),
                        propq, get_secbits(nid), get_oqsalg_idx(nid),
                        get_reverseshare(nid));
}

/* Workaround for not functioning EC PARAM initialization
 * TBD, check https://github.com/openssl/openssl/issues/16989
 */
EVP_PKEY *setECParams(EVP_PKEY *eck, int nid) {
    const unsigned char p256params[] = {0x06, 0x08, 0x2a, 0x86, 0x48,
                                        0xce, 0x3d, 0x03, 0x01, 0x07};
    const unsigned char p384params[] = {0x06, 0x05, 0x2b, 0x81,
                                        0x04, 0x00, 0x22};
    const unsigned char p521params[] = {0x06, 0x05, 0x2b, 0x81,
                                        0x04, 0x00, 0x23};
    const unsigned char bp256params[] = {0x06, 0x09, 0x2b, 0x24, 0x03, 0x03,
                                         0x02, 0x08, 0x01, 0x01, 0x07};
    const unsigned char bp384params[] = {0x06, 0x09, 0x2b, 0x24, 0x03, 0x03,
                                         0x02, 0x08, 0x01, 0x01, 0x0b};

    const unsigned char *params;
    switch (nid) {
    case NID_X9_62_prime256v1:
        params = p256params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p256params));
    case NID_secp384r1:
        params = p384params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p384params));
    case NID_secp521r1:
        params = p521params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(p521params));
    case NID_brainpoolP256r1:
        params = bp256params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(bp256params));
    case NID_brainpoolP384r1:
        params = bp384params;
        return d2i_KeyParams(EVP_PKEY_EC, &eck, &params, sizeof(bp384params));
    default:
        return NULL;
    }
}

/* Key codes */

static const OQSX_EVP_INFO nids_sig[] = {
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 72}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1, 0, 97, 167, 48, 104},       // 192 bit
    {EVP_PKEY_EC, NID_secp521r1, 0, 133, 223, 66, 141},      // 256 bit
    {EVP_PKEY_EC, NID_brainpoolP256r1, 0, 65, 122, 32, 72},  // 256 bit
    {EVP_PKEY_EC, NID_brainpoolP384r1, 0, 97, 171, 48, 104}, // 384 bit
    {EVP_PKEY_RSA, NID_rsaEncryption, 0, 398, 1770, 0, 384}, // 128 bit
    {EVP_PKEY_RSA, NID_rsaEncryption, 0, 270, 1193, 0, 256}, // 112 bit
    {EVP_PKEY_ED25519, NID_ED25519, 1, 32, 32, 32, 72},      // 128 bit
    {EVP_PKEY_ED448, NID_ED448, 1, 57, 57, 57, 122},         // 192 bit

};
// These two array need to stay synced:
// note only leading 4 chars of alg name are checked
static const char *OQSX_ECP_NAMES[] = {
    "p256", "p384", "p521", "SecP256r1", "SecP384r1", "SecP521r1", 0};
static const OQSX_EVP_INFO nids_ecp[] = {
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 0}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1, 0, 97, 167, 48, 0},        // 192 bit
    {EVP_PKEY_EC, NID_secp521r1, 0, 133, 223, 66, 0},       // 256 bit
    {EVP_PKEY_EC, NID_X9_62_prime256v1, 0, 65, 121, 32, 0}, // 128 bit
    {EVP_PKEY_EC, NID_secp384r1, 0, 97, 167, 48, 0},        // 192 bit
    {EVP_PKEY_EC, NID_secp521r1, 0, 133, 223, 66, 0},       // 256 bit
    {0, 0, 0, 0, 0, 0, 0}                                   // 256 bit
};

// These two array need to stay synced:
// note only leading 4 chars of alg name are checked
static const char *OQSX_ECX_NAMES[] = {"x25519", "x448", "X25519", "X448", 0};
static const OQSX_EVP_INFO nids_ecx[] = {
    {EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
    {EVP_PKEY_X448, 0, 1, 56, 56, 56, 0},   // 192 bit
    {EVP_PKEY_X25519, 0, 1, 32, 32, 32, 0}, // 128 bit
    {EVP_PKEY_X448, 0, 1, 56, 56, 56, 0},   // 192 bit
    {0, 0, 0, 0, 0, 0, 0}                   // 256 bit
};

static int oqsx_hybsig_init(int bit_security, OQSX_EVP_CTX *evp_ctx,
                            char *algname) {
    int ret = 1;
    int idx = (bit_security - 128) / 64;
    ON_ERR_GOTO(idx < 0 || idx > 5, err_init);

    if (!strncmp(algname, "rsa", 3) || !strncmp(algname, "pss", 3)) {
        idx += 5;
        if (bit_security == 112)
            idx += 1;
    } else if (algname[0] != 'p' && algname[0] != 'e') {
        if (algname[0] == 'b') {   // bp
            if (algname[2] == '2') // bp256
                idx += 1;
        } else {
            OQS_KEY_PRINTF2("OQS KEY: Incorrect hybrid name: %s\n", algname);
            ret = 0;
            goto err_init;
        }
    }

    ON_ERR_GOTO(idx < 0 || idx > 6, err_init);

    if (algname[0] == 'e') // ED25519 or ED448
    {
        evp_ctx->evp_info = &nids_sig[idx + 7];

        evp_ctx->keyParam = EVP_PKEY_new();
        ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err_init);

        ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
        ON_ERR_SET_GOTO(ret <= 0, ret, -1, err_init);

        evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
        ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err_init);
    } else {
        evp_ctx->evp_info = &nids_sig[idx];

        evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
        ON_ERR_GOTO(!evp_ctx->ctx, err_init);

        if (idx < 5) { // EC
            ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
            ON_ERR_GOTO(ret <= 0, err_init);

            ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(
                evp_ctx->ctx, evp_ctx->evp_info->nid);
            ON_ERR_GOTO(ret <= 0, free_evp_ctx);

            ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
            ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, free_evp_ctx);
        }
    }
    // RSA bit length set only during keygen
    goto err_init;

free_evp_ctx:
    EVP_PKEY_CTX_free(evp_ctx->ctx);
    evp_ctx->ctx = NULL;

err_init:
    return ret;
}

static const int oqshybkem_init_ecp(char *tls_name, OQSX_EVP_CTX *evp_ctx) {
    int ret = 1;
    int idx = 0;

    while (idx < OSSL_NELEM(OQSX_ECP_NAMES)) {
        if (!strncmp(tls_name, OQSX_ECP_NAMES[idx], (idx < 3) ? 4 : 7))
            break;
        idx++;
    }
    ON_ERR_GOTO(idx < 0 || idx > 6, err_init_ecp);

    evp_ctx->evp_info = &nids_ecp[idx];

    evp_ctx->ctx = EVP_PKEY_CTX_new_id(evp_ctx->evp_info->keytype, NULL);
    ON_ERR_GOTO(!evp_ctx->ctx, err_init_ecp);

    ret = EVP_PKEY_paramgen_init(evp_ctx->ctx);
    ON_ERR_GOTO(ret <= 0, err_init_ecp);

    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(evp_ctx->ctx,
                                                 evp_ctx->evp_info->nid);
    ON_ERR_GOTO(ret <= 0, err_init_ecp);

    ret = EVP_PKEY_paramgen(evp_ctx->ctx, &evp_ctx->keyParam);
    ON_ERR_GOTO(ret <= 0 || !evp_ctx->keyParam, err_init_ecp);

err_init_ecp:
    return ret;
}

static const int oqshybkem_init_ecx(char *tls_name, OQSX_EVP_CTX *evp_ctx) {
    int ret = 1;
    int idx = 0;

    while (idx < OSSL_NELEM(OQSX_ECX_NAMES)) {
        if (!strncmp(tls_name, OQSX_ECX_NAMES[idx], 4))
            break;
        idx++;
    }
    ON_ERR_GOTO(idx < 0 || idx > 4, err_init_ecx);

    evp_ctx->evp_info = &nids_ecx[idx];

    evp_ctx->keyParam = EVP_PKEY_new();
    ON_ERR_SET_GOTO(!evp_ctx->keyParam, ret, -1, err_init_ecx);

    ret = EVP_PKEY_set_type(evp_ctx->keyParam, evp_ctx->evp_info->keytype);
    ON_ERR_SET_GOTO(ret <= 0, ret, -1, err_init_ecx);

    evp_ctx->ctx = EVP_PKEY_CTX_new(evp_ctx->keyParam, NULL);
    ON_ERR_SET_GOTO(!evp_ctx->ctx, ret, -1, err_init_ecx);

err_init_ecx:
    return ret;
}

/* Re-create OQSX_KEY from encoding(s): Same end-state as after ken-gen */
static OQSX_KEY *oqsx_key_op(const X509_ALGOR *palg, const unsigned char *p,
                             int plen, oqsx_key_op_t op, OSSL_LIB_CTX *libctx,
                             const char *propq) {
    OQSX_KEY *key = NULL;
    void **privkey, **pubkey;
    int nid = NID_undef;
    int ret = 0;

    OQS_KEY_PRINTF2("OQSX KEY: key_op called with data of len %d\n", plen);
    if (palg != NULL) {
        int ptype;

        /* Algorithm parameters must be absent */
        X509_ALGOR_get0(NULL, &ptype, NULL, palg);
        if (ptype != V_ASN1_UNDEF || !palg || !palg->algorithm) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }
        nid = OBJ_obj2nid(palg->algorithm);
    }

    if (p == NULL || nid == EVP_PKEY_NONE || nid == NID_undef) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
        return 0;
    }

    key = oqsx_key_new_from_nid(libctx, propq, nid);
    if (key == NULL) {
        ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    OQS_KEY_PRINTF2("OQSX KEY: Recreated OQSX key %s\n", key->tls_name);

    if (op == KEY_OP_PUBLIC) {
        if (key->pubkeylen != plen) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            goto err_key_op;
        }
        if (oqsx_key_allocate_keymaterial(key, 0)) {
            ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
            goto err_key_op;
        }
        memcpy(key->pubkey, p, plen);
    } else {
        uint32_t classical_privatekey_len = 0;
        // for plain OQS keys, we expect OQS priv||OQS pub key
        size_t actualprivkeylen = key->privkeylen;
        // for hybrid keys, we expect classic priv key||OQS priv key||OQS
        // pub key classic pub key must/can be re-created from classic
        // private key
        if (key->keytype == KEY_TYPE_CMP_SIG) {
            uint32_t privlen = 0;
            size_t publen = 0;
            size_t previous_privlen = 0;
            size_t previous_publen = 0;
            size_t temp_pub_len, temp_priv_len;
            char *temp_priv, *temp_pub;
            int pqc_pub_enc = 0;
            int i;

            // check if key is the right size
            for (i = 0; i < key->numkeys; i++) {
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) ==
                    NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                privlen = key->privkeylen_cmp[i];
                if (get_oqsname_fromtls(name) == 0) { // classical key
                    publen = 0;
                } else {                            // PQC key
                    publen = key->pubkeylen_cmp[i]; // pubkey in
                                                    // PQC privkey
                                                    // is OPTIONAL
                }
                previous_privlen += privlen;
                previous_publen += publen;
                OPENSSL_free(name);
            }
            if (previous_privlen != plen) {
                // is ok, PQC pubkey might be in privkey
                pqc_pub_enc = 1;
                if (previous_privlen + previous_publen != plen) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                if (oqsx_key_allocate_keymaterial(key, 0)) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err_key_op;
                }
            }
            if (oqsx_key_allocate_keymaterial(key, 1)) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                goto err_key_op;
            }
            temp_priv_len = previous_privlen;
            temp_pub_len = previous_publen;
            temp_priv = OPENSSL_secure_zalloc(temp_priv_len);
            temp_pub = OPENSSL_secure_zalloc(temp_pub_len);
            previous_privlen = 0;
            previous_publen = 0;
            for (i = 0; i < key->numkeys; i++) {
                size_t classic_publen = 0;
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) ==
                    NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                    OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                    goto err_key_op;
                }
                if (get_oqsname_fromtls(name) == 0) { // classical key
                    publen = 0; // no pubkey encoded with privkey
                                // on classical keys. will
                                // recreate the pubkey later
                    if (key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                            ->keytype ==
                        EVP_PKEY_RSA) { // get the RSA real key size
                        if (previous_privlen + previous_publen + 4 > plen) {
                            OPENSSL_free(name);
                            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            goto err_key_op;
                        }
                        unsigned char *enc_len =
                            (unsigned char *)OPENSSL_strndup(
                                (const char *)(p + previous_privlen +
                                               previous_publen),
                                4);
                        OPENSSL_cleanse(enc_len, 2);
                        DECODE_UINT32(privlen, enc_len);
                        privlen += 4;
                        OPENSSL_free(enc_len);
                        if (privlen > key->privkeylen_cmp[i]) {
                            OPENSSL_free(name);
                            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            goto err_key_op;
                        }
                        key->privkeylen_cmp[i] = privlen;
                    } else
                        privlen = key->privkeylen_cmp[i];
                } else { // PQC key
                    privlen = key->privkeylen_cmp[i];
                    if (pqc_pub_enc)
                        publen = key->pubkeylen_cmp[i];
                    else
                        publen = 0;
                }
                if (previous_privlen + previous_publen + privlen > plen) {
                    OPENSSL_free(name);
                    OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
                    OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                memcpy(temp_priv + previous_privlen,
                       p + previous_privlen + previous_publen, privlen);
                memcpy(temp_pub + previous_publen,
                       p + privlen + previous_privlen + previous_publen,
                       publen);
                previous_privlen += privlen;
                previous_publen += publen;
                OPENSSL_free(name);
            }
            memcpy(key->privkey, temp_priv, previous_privlen);
            memcpy(key->pubkey, temp_pub, previous_publen);
            OPENSSL_secure_clear_free(temp_priv, temp_priv_len);
            OPENSSL_secure_clear_free(temp_pub, temp_pub_len);
        } else {
            // TODO_QKD: properly integrate QKD keys
            if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
                if (key->numkeys != 2) {
                    // TODO_QKD: properly integrate QKD triple hybrid
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                size_t expected_pq_privkey_len =
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key +
                    QKD_KEY_SIZE;

#ifndef NOPUBKEY_IN_PRIVKEY
                expected_pq_privkey_len +=
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
#endif

                // For 2-key hybrid (PQ + QKD), the total length should match
                if (plen != expected_pq_privkey_len) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }

                actualprivkeylen = expected_pq_privkey_len;

                // Allocate memory for both private and public keys
                if (oqsx_key_allocate_keymaterial(key, 1)
#ifndef NOPUBKEY_IN_PRIVKEY
                    || oqsx_key_allocate_keymaterial(key, 0)
#endif
                ) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err_key_op;
                }

                // Copy PQ private key first
                memcpy(
                    key->privkey, p,
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key);
                // Copy QKD key at the end
                memcpy(key->privkey + key->oqsx_provider_ctx.oqsx_qs_ctx.kem
                                          ->length_secret_key,
                       p + key->oqsx_provider_ctx.oqsx_qs_ctx.kem
                               ->length_secret_key,
                       QKD_KEY_SIZE);

#ifndef NOPUBKEY_IN_PRIVKEY
                // Handle public key components: PQ public key and QKD key ID
                unsigned char *pubkey = (unsigned char *)key->pubkey;

                size_t pq_public_offset =
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key +
                    QKD_KEY_SIZE;
                size_t qkd_id_offset =
                    pq_public_offset +
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;

                memcpy(
                    pubkey, p + pq_public_offset,
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key);

                memcpy(pubkey + key->oqsx_provider_ctx.oqsx_qs_ctx.kem
                                    ->length_public_key,
                       p + qkd_id_offset, QKD_KSID_SIZE);
#endif
            } else {
                if (key->numkeys == 2) {
                    size_t expected_pq_privkey_len =
                        key->oqsx_provider_ctx.oqsx_qs_ctx.kem
                            ->length_secret_key;
#ifndef NOPUBKEY_IN_PRIVKEY
                    expected_pq_privkey_len +=
                        key->oqsx_provider_ctx.oqsx_qs_ctx.kem
                            ->length_public_key;
#endif
                    if (plen > (SIZE_OF_UINT32 + expected_pq_privkey_len)) {
                        size_t max_classical_privkey_len =
                            key->evp_info->length_private_key;
                        size_t space_for_classical_privkey =
                            plen - expected_pq_privkey_len - SIZE_OF_UINT32;
                        if (space_for_classical_privkey >
                            max_classical_privkey_len) {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            goto err_key_op;
                        }
                        DECODE_UINT32(classical_privatekey_len,
                                      p); // actual classic key len
                        if (classical_privatekey_len !=
                            space_for_classical_privkey) {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            goto err_key_op;
                        }
                    } else {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto err_key_op;
                    }
                    actualprivkeylen -= (key->evp_info->length_private_key -
                                         classical_privatekey_len);
                }
#ifdef NOPUBKEY_IN_PRIVKEY
                if (actualprivkeylen != plen) {
                    OQS_KEY_PRINTF3("OQSX KEY: private key with "
                                    "unexpected length %d vs %d\n",
                                    plen, (int)(actualprivkeylen));
#else
                if (actualprivkeylen + oqsx_key_get_oqs_public_key_len(key) !=
                    plen) {
                    OQS_KEY_PRINTF3(
                        "OQSX KEY: private key with unexpected length "
                        "%d vs %d\n",
                        plen,
                        (int)(actualprivkeylen +
                              oqsx_key_get_oqs_public_key_len(key)));
#endif
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                if (oqsx_key_allocate_keymaterial(key, 1)
#ifndef NOPUBKEY_IN_PRIVKEY
                    || oqsx_key_allocate_keymaterial(key, 0)
#endif
                ) {
                    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                    goto err_key_op;
                }
                // first populate private key data
                memcpy(key->privkey, p, actualprivkeylen);
#ifndef NOPUBKEY_IN_PRIVKEY
                // only enough data to fill public OQS key component
                if (oqsx_key_get_oqs_public_key_len(key) !=
                    plen - actualprivkeylen) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto err_key_op;
                }
                // populate OQS public key structure
                if (key->numkeys == 2) {
                    unsigned char *pubkey = (unsigned char *)key->pubkey;
                    ENCODE_UINT32(pubkey, key->evp_info->length_public_key);
                    if (key->reverse_share) {
                        memcpy(pubkey + SIZE_OF_UINT32, p + actualprivkeylen,
                               plen - actualprivkeylen);
                    } else {
                        memcpy(pubkey + SIZE_OF_UINT32 +
                                   key->evp_info->length_public_key,
                               p + actualprivkeylen, plen - actualprivkeylen);
                    }
                } else
                    memcpy(key->pubkey, p + key->privkeylen,
                           plen - key->privkeylen);
#endif
            }
        }
    }
    if (!oqsx_key_set_composites(key,
                                 key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                                     key->keytype == KEY_TYPE_ECX_HYB_KEM ||
                                     key->keytype == KEY_TYPE_QKD_HYB_KEM) ||
        !oqsx_key_recreate_classickey(key, op))
        goto err_key_op;

    return key;

err_key_op:
    oqsx_key_free(key);
    return NULL;
}

/* Recreate EVP data structure after import. RetVal 0 is error. */
static int oqsx_key_recreate_classickey(OQSX_KEY *key, oqsx_key_op_t op) {
    if (key->keytype == KEY_TYPE_CMP_SIG) {
        int i;
        if (op == KEY_OP_PUBLIC) {
            for (i = 0; i < key->numkeys; i++) {
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) ==
                    NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
                const unsigned char *enc_pubkey = key->comp_pubkey[i];

                if (get_oqsname_fromtls(name) == 0) {
                    if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                             ->raw_key_support) {
                        EVP_PKEY *npk = EVP_PKEY_new();
                        if (key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype != EVP_PKEY_RSA) {
                            npk = setECParams(npk,
                                              key->oqsx_provider_ctx
                                                  .oqsx_evp_ctx->evp_info->nid);
                        }
                        key->classical_pkey = d2i_PublicKey(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            &npk, &enc_pubkey, key->pubkeylen_cmp[i]);
                    } else
                        key->classical_pkey = EVP_PKEY_new_raw_public_key(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            NULL, enc_pubkey, key->pubkeylen_cmp[i]);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        OPENSSL_free(name);
                        goto rec_err;
                    }
                }
                OPENSSL_free(name);
            }
        }

        if (op == KEY_OP_PRIVATE) {
            for (i = 0; i < key->numkeys; i++) {
                char *name;
                if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) ==
                    NULL) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
                if (get_oqsname_fromtls(name) == 0) {
                    const unsigned char *enc_privkey = key->comp_privkey[i];
                    if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                             ->raw_key_support) {
                        EVP_PKEY *npk;
                        key->classical_pkey = d2i_PrivateKey(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            NULL, &enc_privkey, key->privkeylen_cmp[i]);
                    } else {
                        key->classical_pkey = EVP_PKEY_new_raw_private_key(
                            key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                                ->keytype,
                            NULL, enc_privkey, key->privkeylen_cmp[i]);
                    }
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        OPENSSL_free(name);
                        goto rec_err;
                    }
                    if (!key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                             ->raw_key_support) {
                        unsigned char *comp_pubkey = key->comp_pubkey[i];
                        int pubkeylen =
                            i2d_PublicKey(key->classical_pkey, &comp_pubkey);
                        if (pubkeylen != key->oqsx_provider_ctx.oqsx_evp_ctx
                                             ->evp_info->length_public_key) {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            OPENSSL_free(name);
                            goto rec_err;
                        }
                    } else {
                        size_t pubkeylen = key->pubkeylen_cmp[i];
                        int ret = EVP_PKEY_get_raw_public_key(
                            key->classical_pkey, key->comp_pubkey[i],
                            &pubkeylen);
                        if (ret <= 0) {
                            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                            OPENSSL_free(name);
                            goto rec_err;
                        }
                    }
                }
                OPENSSL_free(name);
            }
        }
    } else {
        if (key->numkeys == 2) { // hybrid key
            int idx_classic;
            oqsx_comp_set_idx(key, &idx_classic, NULL, NULL);

            uint32_t classical_pubkey_len = 0;
            uint32_t classical_privkey_len = 0;
            if (!key->evp_info) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_EVPINFO_MISSING);
                goto rec_err;
            }
            if (op == KEY_OP_PUBLIC) {
                const unsigned char *enc_pubkey = key->comp_pubkey[idx_classic];
                DECODE_UINT32(classical_pubkey_len, key->pubkey);
                if (classical_pubkey_len > key->evp_info->length_public_key) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
                if (key->evp_info->raw_key_support) {
                    key->classical_pkey = EVP_PKEY_new_raw_public_key(
                        key->evp_info->keytype, NULL, enc_pubkey,
                        classical_pubkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
                } else {
                    EVP_PKEY *npk = EVP_PKEY_new();
                    if (key->evp_info->keytype != EVP_PKEY_RSA) {
                        npk = setECParams(npk, key->evp_info->nid);
                    }
                    key->classical_pkey =
                        d2i_PublicKey(key->evp_info->keytype, &npk, &enc_pubkey,
                                      classical_pubkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        EVP_PKEY_free(npk);
                        goto rec_err;
                    }
                }
            }
            if (op == KEY_OP_PRIVATE) {
                DECODE_UINT32(classical_privkey_len, key->privkey);
                if (classical_privkey_len > key->evp_info->length_private_key) {
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    goto rec_err;
                }
                const unsigned char *enc_privkey =
                    key->comp_privkey[idx_classic];
                unsigned char *enc_pubkey = key->comp_pubkey[idx_classic];
                if (key->evp_info->raw_key_support) {
                    key->classical_pkey = EVP_PKEY_new_raw_private_key(
                        key->evp_info->keytype, NULL, enc_privkey,
                        classical_privkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#ifndef NOPUBKEY_IN_PRIVKEY
                    // re-create classic public key part from
                    // private key:
                    size_t pubkeylen;

                    EVP_PKEY_get_raw_public_key(key->classical_pkey, NULL,
                                                &pubkeylen);
                    if (pubkeylen != key->evp_info->length_public_key ||
                        EVP_PKEY_get_raw_public_key(
                            key->classical_pkey, enc_pubkey, &pubkeylen) != 1) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#endif
                } else {
                    key->classical_pkey =
                        d2i_PrivateKey(key->evp_info->keytype, NULL,
                                       &enc_privkey, classical_privkey_len);
                    if (!key->classical_pkey) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#ifndef NOPUBKEY_IN_PRIVKEY
                    // re-create classic public key part from
                    // private key:
                    int pubkeylen =
                        i2d_PublicKey(key->classical_pkey, &enc_pubkey);
                    if (pubkeylen != key->evp_info->length_public_key) {
                        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                        goto rec_err;
                    }
#endif
                }
            }
        }
    }

    return 1;

rec_err:
    return 0;
}

OQSX_KEY *oqsx_key_from_x509pubkey(const X509_PUBKEY *xpk, OSSL_LIB_CTX *libctx,
                                   const char *propq) {
    const unsigned char *p;
    int plen;
    X509_ALGOR *palg;
    OQSX_KEY *oqsx = NULL;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    ASN1_OCTET_STRING *oct = NULL;
    const unsigned char *buf;
    unsigned char *concat_key;
    int count, aux, i, buflen;

    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }
    if (get_keytype(OBJ_obj2nid(palg->algorithm)) == KEY_TYPE_CMP_SIG) {
        sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, plen);
        if (sk == NULL) {
            sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return NULL;
        } else {
            count = sk_ASN1_TYPE_num(sk);
            concat_key =
                OPENSSL_zalloc(plen); // concat_key is allocated with plen,
                                      // which is the max value for pubkey

            aux = 0;
            for (i = 0; i < count; i++) {
                aType =
                    sk_ASN1_TYPE_pop(sk); // this remove in FILO order, but we
                                          // need this in the opposite order
                buf = aType->value.sequence->data;
                buflen = aType->value.sequence->length;
                aux += buflen;
                memcpy(concat_key + plen - 1 - aux, buf,
                       buflen); // fill concat_key starting at the end
                ASN1_TYPE_free(aType);
            }

            p = OPENSSL_memdup(concat_key + plen - 1 - aux,
                               aux); // copy used memory on concat_key to p
            OPENSSL_clear_free(concat_key, plen);
            plen = aux; // update plen value
            sk_ASN1_TYPE_free(sk);
        }
    }
    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);
    if (get_keytype(OBJ_obj2nid(palg->algorithm)) == KEY_TYPE_CMP_SIG)
        OPENSSL_clear_free((unsigned char *)p, plen);
    return oqsx;
}

OQSX_KEY *oqsx_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8inf,
                              OSSL_LIB_CTX *libctx, const char *propq) {
    OQSX_KEY *oqsx = NULL;
    const unsigned char *p;
    int plen;
    ASN1_OCTET_STRING *oct = NULL;
    const X509_ALGOR *palg;
    STACK_OF(ASN1_TYPE) *sk = NULL;
    ASN1_TYPE *aType = NULL;
    unsigned char *concat_key;
    const unsigned char *buf;
    int count, aux, i, buflen, key_diff = 0;

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8inf))
        return 0;

    if (get_keytype(OBJ_obj2nid(palg->algorithm)) != KEY_TYPE_CMP_SIG) {
        oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
        if (oct == NULL) {
            p = NULL;
            plen = 0;
        } else {
            p = ASN1_STRING_get0_data(oct);
            plen = ASN1_STRING_length(oct);
        }
    } else {
        sk = d2i_ASN1_SEQUENCE_ANY(NULL, &p, plen);
        if (sk == NULL) {
            sk_ASN1_TYPE_pop_free(sk, &ASN1_TYPE_free);
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return NULL;
        } else {
            count = sk_ASN1_TYPE_num(sk);
            plen = 2 * plen; // get more than necessary in case its needed
            concat_key = OPENSSL_zalloc(plen);
            PKCS8_PRIV_KEY_INFO *p8inf_internal = NULL;
            const X509_ALGOR *palg_internal;
            int keytype, nid;

            aux = 0;
            for (i = 0; i < count; i++) {
                aType =
                    sk_ASN1_TYPE_pop(sk); // this remove in FILO order, but we
                                          // need this in the opposite order
                p8inf_internal = PKCS8_PRIV_KEY_INFO_new();
                nid = 0;
                char *name;
                if ((name = get_cmpname(OBJ_obj2nid(palg->algorithm),
                                        count - 1 - i)) == NULL) {
                    ASN1_TYPE_free(aType);
                    OPENSSL_clear_free(concat_key, plen);
                    PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                    sk_ASN1_TYPE_free(sk);
                    ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                    return NULL;
                }
                buflen = aType->value.sequence->length;
                const unsigned char *buf2 = aType->value.sequence->data;

                p8inf_internal =
                    d2i_PKCS8_PRIV_KEY_INFO(&p8inf_internal, &buf2, buflen);
                if (!PKCS8_pkey_get0(NULL, &buf, &buflen, &palg_internal,
                                     p8inf_internal)) {
                    OPENSSL_free(name);
                    ASN1_TYPE_free(aType);
                    PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                    OPENSSL_clear_free(concat_key, plen);
                    sk_ASN1_TYPE_free(sk);
                    return NULL;
                }

                keytype = OBJ_obj2nid(palg_internal->algorithm);

                // Checking OPTIONAL params on EC
                if (keytype == EVP_PKEY_EC) {
                    int j;
                    nid = OBJ_obj2nid(palg_internal->parameter->value.object);
                    for (j = 0; j < OSSL_NELEM(nids_sig); j++) {
                        if ((nids_sig[j].nid == nid) &&
                            (nids_sig[j].length_private_key >
                             buflen)) { // check if the curve is the
                                        // same and if the key len is
                                        // smaller than the max key
                                        // size
                            EVP_PKEY *ec_pkey;
                            OSSL_PARAM params[3];
                            int include_pub = 1;
                            const unsigned char *buf3 =
                                aType->value.sequence->data;
                            unsigned char *buf4, *buf5;

                            if (buflen != nids_sig[j].kex_length_secret +
                                              7) { // no OPTIONAL
                                                   // ECParameter and no
                                                   // OPTIONAL Pubkey
                                OPENSSL_free(name);
                                ASN1_TYPE_free(aType);
                                PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                                OPENSSL_clear_free(concat_key, plen);
                                sk_ASN1_TYPE_free(sk);
                                return NULL;
                            }
                            ec_pkey = EVP_PKEY_new();
                            d2i_PrivateKey(
                                EVP_PKEY_EC, &ec_pkey, &buf3,
                                aType->value.sequence->length); // create
                                                                // a new
                                                                // EVP_PKEY
                                                                // using
                                                                // ec
                                                                // priv
                                                                // key

                            // set parameters for the
                            // new priv key format
                            params[0] = OSSL_PARAM_construct_int(
                                OSSL_PKEY_PARAM_EC_INCLUDE_PUBLIC,
                                &include_pub); // add
                                               // pubkey
                                               // to
                                               // priv
                                               // key
                            params[1] = OSSL_PARAM_construct_utf8_string(
                                OSSL_PKEY_PARAM_EC_ENCODING,
                                OSSL_PKEY_EC_ENCODING_GROUP,
                                0); // add ECParam to
                                    // the priv key
                            params[2] = OSSL_PARAM_construct_end();
                            EVP_PKEY_set_params(ec_pkey, params);

                            buf4 =
                                OPENSSL_malloc(nids_sig[j].length_private_key);
                            buf5 = buf4;
                            buflen = i2d_PrivateKey(ec_pkey,
                                                    &buf5); // encode priv
                                                            // key
                                                            // including
                                                            // parameters

                            aux += buflen;
                            memcpy(concat_key + plen - 1 - aux, buf4,
                                   buflen); // fill
                                            // concat_key
                                            // starting at
                                            // the end

                            EVP_PKEY_free(ec_pkey);
                            OPENSSL_clear_free(buf4, buflen);
                            break;
                        }
                    }
                    if (j == OSSL_NELEM(nids_sig))
                        nid = 0; // buflen is already with the
                                 // correct size, changing nid
                                 // to memcpy at the end
                }

                // if is a RSA key the actual encoding size might
                // be different from max size we calculate that
                // difference for to facilitate the key
                // reconstruction
                if (keytype == EVP_PKEY_RSA) {
                    if (name[3] == '3') // 3072
                        key_diff = nids_sig[5].length_private_key - buflen;
                    else // 2048
                        key_diff = nids_sig[6].length_private_key - buflen;
                }

                // removing extra OTECT STRING from ED25519 and ED448 keys
                if ((keytype == EVP_PKEY_ED25519) ||
                    (keytype == EVP_PKEY_ED448)) {
                    ASN1_OCTET_STRING *ed_octet = NULL;
                    ed_octet = d2i_ASN1_OCTET_STRING(&ed_octet, &buf, buflen);
                    aux += ed_octet->length;
                    memcpy(concat_key + plen - 1 - aux, ed_octet->data,
                           ed_octet->length);
                    nid = 1; // setting to non zero value so the key is not
                             // copied again
                    ASN1_OCTET_STRING_free(ed_octet);
                }

                if (!nid) {
                    aux += buflen;
                    memcpy(concat_key + plen - 1 - aux, buf,
                           buflen); // fill concat_key
                                    // starting at the end
                }

                OPENSSL_free(name);
                PKCS8_PRIV_KEY_INFO_free(p8inf_internal);
                ASN1_TYPE_free(aType);
            }

            p = OPENSSL_memdup(concat_key + plen - 1 - aux, aux);
            OPENSSL_clear_free(concat_key, plen);
            plen = aux; // update plen to correct size
            sk_ASN1_TYPE_free(sk);
        }
    }

    oqsx = oqsx_key_op(palg, p, plen + key_diff, KEY_OP_PRIVATE, libctx, propq);
    if (get_keytype(OBJ_obj2nid(palg->algorithm)) != KEY_TYPE_CMP_SIG) {
        ASN1_OCTET_STRING_free(oct);
    } else {
        OPENSSL_clear_free((unsigned char *)p,
                           plen); // for COMPOSITE p include both privkey
    }
    return oqsx;
}

static const int (*init_kex_fun[])(char *, OQSX_EVP_CTX *) = {
    oqshybkem_init_ecp, oqshybkem_init_ecx};
extern const char *oqs_oid_alg_list[];

OQSX_KEY *oqsx_key_new(OSSL_LIB_CTX *libctx, char *oqs_name, char *tls_name,
                       int primitive, const char *propq, int bit_security,
                       int alg_idx, int reverse_share) {
    OQSX_KEY *ret =
        OPENSSL_zalloc(sizeof(*ret)); // ensure all component pointers are NULL
    OQSX_EVP_CTX *evp_ctx = NULL;
    int ret2 = 0, i;

    if (ret == NULL) {
        QKD_DEBUG("Memory allocation failed");
        goto err;
    }

    QKD_DEBUG("oqsx_key_new()");

#ifdef OQS_PROVIDER_NOATOMIC
    ret->lock = CRYPTO_THREAD_lock_new();
    ON_ERR_GOTO(!ret->lock, err);
#endif

    if (oqs_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No OQS key name provided:\n");
        goto err;
    }

    if (tls_name == NULL) {
        OQS_KEY_PRINTF("OQSX_KEY: Fatal error: No TLS key name provided:\n");
        goto err;
    }

    switch (primitive) {
    case KEY_TYPE_KEM:
        ret->numkeys = 1;
        ret->comp_privkey = OPENSSL_malloc(sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->oqsx_provider_ctx.oqsx_evp_ctx = NULL;
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(stderr,
                    "Could not create OQS KEM algorithm %s. Enabled "
                    "in liboqs?\n",
                    oqs_name);
            goto err;
        }
        ret->privkeylen =
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
        ret->pubkeylen =
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        ret->keytype = KEY_TYPE_KEM;
        break;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
        ret->reverse_share = reverse_share;
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(stderr,
                    "Could not create OQS KEM algorithm %s. Enabled "
                    "in liboqs?\n",
                    oqs_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 =
            (init_kex_fun[primitive - KEY_TYPE_ECP_HYB_KEM])(tls_name, evp_ctx);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->keyParam || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->privkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key +
            evp_ctx->evp_info->length_private_key;
        ret->pubkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key +
            evp_ctx->evp_info->length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
        ret->evp_info = evp_ctx->evp_info;
        break;
    case KEY_TYPE_QKD_HYB_KEM:
        // TODO_QKD: implement proper key handling here
        //  Initialize PQ KEM context
        ret->oqsx_provider_ctx.oqsx_qs_ctx.kem = OQS_KEM_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.kem) {
            fprintf(stderr, "Could not create OQS KEM algorithm %s\n",
                    oqs_name);
            goto err;
        }

        // TODO_QKD: ensure this is never called for the responder
        if (oqs_init_qkd_context(ret, true) != OQS_SUCCESS) { // Assume initiator by default
            fprintf(stderr, "Could not initialize QKD context\n"); 
            goto err;
        }

        QKD_DEBUG(
            "PQ key sizes: public=%ld, private=%ld, ciphertext=%ld, shared=%ld",
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key,
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key,
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_ciphertext,
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret);

        // Allocate memory for composite keys
        ret->numkeys = 2; // QKD + PQ hybrid
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);

        // Calculate key lengths including QKD components
        ret->privkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 + // Size headers
            32 +                                  // QKD symmetric key
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key; // PQ key

        ret->pubkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 + // Size headers
            256 +                                 // QKD ID
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key; // PQ key
        ret->keytype = primitive;
        break;
    case KEY_TYPE_HYB_SIG:
        ret->oqsx_provider_ctx.oqsx_qs_ctx.sig = OQS_SIG_new(oqs_name);
        if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
            fprintf(stderr,
                    "Could not create OQS signature algorithm %s. "
                    "Enabled in "
                    "liboqs?\n",
                    oqs_name);
            goto err;
        }
        evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
        ON_ERR_GOTO(!evp_ctx, err);

        ret2 = oqsx_hybsig_init(bit_security, evp_ctx, tls_name);
        ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);

        ret->numkeys = 2;
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ON_ERR_GOTO(!ret->comp_privkey || !ret->comp_pubkey, err);
        ret->privkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key +
            evp_ctx->evp_info->length_private_key;
        ret->pubkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 +
            ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key +
            evp_ctx->evp_info->length_public_key;
        ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
        ret->keytype = primitive;
        ret->evp_info = evp_ctx->evp_info;
        break;
    case KEY_TYPE_CMP_SIG:
        ret->numkeys = 2;
        ret->privkeylen = 0;
        ret->pubkeylen = 0;
        ret->privkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
        ret->pubkeylen_cmp = OPENSSL_malloc(ret->numkeys * sizeof(size_t));
        ret->comp_privkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));
        ret->comp_pubkey = OPENSSL_malloc(ret->numkeys * sizeof(void *));

        for (i = 0; i < ret->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(tls_name), i)) == NULL) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                goto err;
            }
            if (get_oqsname_fromtls(name) != 0) {
                ret->oqsx_provider_ctx.oqsx_qs_ctx.sig =
                    OQS_SIG_new(get_oqsname_fromtls(name));
                if (!ret->oqsx_provider_ctx.oqsx_qs_ctx.sig) {
                    fprintf(stderr,
                            "Could not create OQS signature "
                            "algorithm %s. "
                            "Enabled in "
                            "liboqs?A\n",
                            name);
                    goto err;
                }
                ret->privkeylen_cmp[i] =
                    ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_secret_key;
                ret->pubkeylen_cmp[i] =
                    ret->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
            } else {
                evp_ctx = OPENSSL_zalloc(sizeof(OQSX_EVP_CTX));
                ON_ERR_GOTO(!evp_ctx, err);

                ret2 = oqsx_hybsig_init(bit_security, evp_ctx, name);
                ON_ERR_GOTO(ret2 <= 0 || !evp_ctx->ctx, err);
                ret->oqsx_provider_ctx.oqsx_evp_ctx = evp_ctx;
                ret->privkeylen_cmp[i] = ret->oqsx_provider_ctx.oqsx_evp_ctx
                                             ->evp_info->length_private_key;
                ret->pubkeylen_cmp[i] = ret->oqsx_provider_ctx.oqsx_evp_ctx
                                            ->evp_info->length_public_key;
            }
            ret->privkeylen += ret->privkeylen_cmp[i];
            ret->pubkeylen += ret->pubkeylen_cmp[i];
            OPENSSL_free(name);
        }
        ret->keytype = primitive;

        break;
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        primitive);
        goto err;
    }

    ret->libctx = libctx;
    ret->references = 1;
    ret->tls_name = OPENSSL_strdup(tls_name);
    ON_ERR_GOTO(!ret->tls_name, err);
    ret->bit_security = bit_security;

    if (propq != NULL) {
        ret->propq = OPENSSL_strdup(propq);
        ON_ERR_GOTO(!ret->propq, err);
    }

    OQS_KEY_PRINTF2("OQSX_KEY: new key created: %s\n", ret->tls_name);
    OQS_KEY_PRINTF3("OQSX_KEY: new key created: %p (type: %d)\n", ret,
                    ret->keytype);
    return ret;
err:
    ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
#ifdef OQS_PROVIDER_NOATOMIC
    if (ret->lock)
        CRYPTO_THREAD_lock_free(ret->lock);
#endif
    if (ret) {
        OPENSSL_free(ret->tls_name);
        OPENSSL_free(ret->propq);
        OPENSSL_free(ret->comp_privkey);
        OPENSSL_free(ret->comp_pubkey);
    }
    OPENSSL_free(ret);
    return NULL;
}

void oqsx_key_free(OQSX_KEY *key) {
    // TODO_QKD: free QKD specific data
    int refcnt;
    if (key == NULL)
        return;

#ifndef OQS_PROVIDER_NOATOMIC
    refcnt =
        atomic_fetch_sub_explicit(&key->references, 1, memory_order_relaxed) -
        1;
    if (refcnt == 0)
        atomic_thread_fence(memory_order_acquire);
#else
    CRYPTO_atomic_add(&key->references, -1, &refcnt, key->lock);
#endif

    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void *)key, refcnt);
    if (refcnt > 0)
        return;
#ifndef NDEBUG
    assert(refcnt == 0);
#endif

    OPENSSL_free(key->propq);
    OPENSSL_free(key->tls_name);
    OPENSSL_secure_clear_free(key->privkey, key->privkeylen);
    OPENSSL_secure_clear_free(key->pubkey, key->pubkeylen);
    OPENSSL_free(key->comp_pubkey);
    OPENSSL_free(key->comp_privkey);
    if (key->keytype == KEY_TYPE_CMP_SIG) {
        OPENSSL_free(key->privkeylen_cmp);
        OPENSSL_free(key->pubkeylen_cmp);
    }
    if (key->keytype == KEY_TYPE_KEM)
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    else if (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
             key->keytype == KEY_TYPE_ECX_HYB_KEM ||
             key->keytype == KEY_TYPE_QKD_HYB_KEM) {
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    } else
        OQS_SIG_free(key->oqsx_provider_ctx.oqsx_qs_ctx.sig);
    EVP_PKEY_free(key->classical_pkey);
    if (key->oqsx_provider_ctx.oqsx_evp_ctx) {
        EVP_PKEY_CTX_free(key->oqsx_provider_ctx.oqsx_evp_ctx->ctx);
        EVP_PKEY_free(key->oqsx_provider_ctx.oqsx_evp_ctx->keyParam);
        OPENSSL_free(key->oqsx_provider_ctx.oqsx_evp_ctx);
    }

#ifdef OQS_PROVIDER_NOATOMIC
    CRYPTO_THREAD_lock_free(key->lock);
#endif
    OPENSSL_free(key);
}

int oqsx_key_up_ref(OQSX_KEY *key) {
    int refcnt;

#ifndef OQS_PROVIDER_NOATOMIC
    refcnt =
        atomic_fetch_add_explicit(&key->references, 1, memory_order_relaxed) +
        1;
#else
    CRYPTO_atomic_add(&key->references, 1, &refcnt, key->lock);
#endif

    OQS_KEY_PRINTF3("%p:%4d:OQSX_KEY\n", (void *)key, refcnt);
#ifndef NDEBUG
    assert(refcnt > 1);
#endif
    return (refcnt > 1);
}

int oqsx_key_allocate_keymaterial(OQSX_KEY *key, int include_private) {
    int ret = 0, aux = 0;

    if (key->keytype != KEY_TYPE_CMP_SIG)
        aux = SIZE_OF_UINT32;

    if (!key->privkey && include_private) {
        key->privkey = OPENSSL_secure_zalloc(key->privkeylen + aux);
        ON_ERR_SET_GOTO(!key->privkey, ret, 1, err_alloc);
        }
    if (!key->pubkey && !include_private) {
        key->pubkey = OPENSSL_secure_zalloc(key->pubkeylen);
        ON_ERR_SET_GOTO(!key->pubkey, ret, 1, err_alloc);
        }
err_alloc:
    return ret;
}

int oqsx_key_fromdata(OQSX_KEY *key, const OSSL_PARAM params[],
                      int include_private) {
    const OSSL_PARAM *pp1, *pp2;

    int classic_lengths_fixed = key->keytype == KEY_TYPE_ECP_HYB_KEM ||
                               key->keytype == KEY_TYPE_ECX_HYB_KEM;

    OQS_KEY_PRINTF("OQSX Key from data called\n");
    pp1 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    pp2 = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    // at least one parameter must be given
    if (pp1 == NULL && pp2 == NULL) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return 0;
    }
        if (pp1 != NULL) {
            if (pp1->data_type != OSSL_PARAM_OCTET_STRING) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return 0;
            }
            if (key->privkeylen != pp1->data_size) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
                return 0;
            }
            OPENSSL_secure_clear_free(key->privkey, pp1->data_size);
            key->privkey = OPENSSL_secure_malloc(pp1->data_size);
            if (key->privkey == NULL) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(key->privkey, pp1->data, pp1->data_size);
        }
        if (pp2 != NULL) {
            if (pp2->data_type != OSSL_PARAM_OCTET_STRING) {
                OQS_KEY_PRINTF("invalid data type\n");
                return 0;
            }
            if (key->pubkeylen != pp2->data_size) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_SIZE);
                return 0;
            }
            OPENSSL_secure_clear_free(key->pubkey, pp2->data_size);
            key->pubkey = OPENSSL_secure_malloc(pp2->data_size);
            if (key->pubkey == NULL) {
                ERR_raise(ERR_LIB_USER, ERR_R_MALLOC_FAILURE);
                return 0;
            }
            memcpy(key->pubkey, pp2->data, pp2->data_size);
        }
    if (!oqsx_key_set_composites(key, classic_lengths_fixed) ||
        !oqsx_key_recreate_classickey(
            key, key->privkey != NULL ? KEY_OP_PRIVATE : KEY_OP_PUBLIC))
        return 0;
    return 1;
}

// OQS key always the last of the numkeys comp keys
static int oqsx_key_gen_oqs(OQSX_KEY *key, int gen_kem) {
    int idx_pq;
    oqsx_comp_set_idx(key, NULL, &idx_pq, NULL);

    if (gen_kem)
        return OQS_KEM_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.kem,
                               key->comp_pubkey[idx_pq],
                               key->comp_privkey[idx_pq]);
    else {
        return OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig,
                               key->comp_pubkey[idx_pq],
                               key->comp_privkey[idx_pq]);
    }
}

static int oqsx_key_gen_qkd(OQSX_KEY *key) {
    int ret = OQS_SUCCESS;
    int idx_qkd;

    QKD_DEBUG("Starting QKD key generation");

    oqsx_comp_set_idx(key, NULL, NULL, &idx_qkd);
    QKD_DEBUG("Got QKD index: %d", idx_qkd);
    ON_ERR_SET_GOTO(idx_qkd < 0, ret, OQS_ERROR, err);

    // Check key is valid
    QKD_DEBUG("Checking key pointer: %p", key);
    ON_ERR_SET_GOTO(!key, ret, OQS_ERROR, err);

    // Access QKD context through key structure
    QKD_CTX *qkd_ctx = key->qkd_ctx;
    QKD_DEBUG("QKD context pointer: %p", qkd_ctx);
    ON_ERR_SET_GOTO(!qkd_ctx, ret, OQS_ERROR, err);

    // Only initiator should generate initial key
    if (!qkd_ctx->is_initiator) {
        QKD_DEBUG("QKD key generation only for initiator");
        ret = OQS_ERROR;
        goto err;
    }

    QKD_DEBUG("Allocating QKD components");
    // Allocate memory for QKD components
    key->comp_pubkey[idx_qkd] = OPENSSL_malloc(QKD_KSID_SIZE);
    key->comp_privkey[idx_qkd] = OPENSSL_secure_malloc(QKD_KEY_SIZE);

    QKD_DEBUG("Pubkey pointer: %p, Privkey pointer: %p",
              key->comp_pubkey[idx_qkd],
              key->comp_privkey[idx_qkd]);

    if (!key->comp_pubkey[idx_qkd] || !key->comp_privkey[idx_qkd]) {
        QKD_DEBUG("Failed to allocate memory for QKD components");
        ret = OQS_ERROR;
        goto err;
    }

#ifdef ETSI_004_API
    // For ETSI 004: At key generation time, only establish connection to get key ID
    // The actual key retrieval happens later during decapsulation after Bob has
    // established his session with this key ID
    if (!qkd_open_connect(qkd_ctx)) {
        QKD_DEBUG("Failed to establish QKD connection");
        ret = OQS_ERROR;
        goto err;
    }
    
    // Store key ID as public key - this will be sent to Bob
    memcpy(key->comp_pubkey[idx_qkd], qkd_ctx->key_id, QKD_KSID_SIZE);
    
    // Initialize private key to zero - actual key will be retrieved during decapsulation
    memset(key->comp_privkey[idx_qkd], 0, QKD_KEY_SIZE);

#elif defined(ETSI_014_API)
    // For ETSI 014: Get both key ID and key material immediately
    // Bob will later use GET_KEY_WITH_IDS to get his copy
    if (!qkd_get_key(qkd_ctx)) {
        QKD_DEBUG("Failed to get QKD key material");
        ret = OQS_ERROR;
        goto err;
    }
    
    // Store both public key ID and private key
    memcpy(key->comp_pubkey[idx_qkd], qkd_ctx->key_id, QKD_KSID_SIZE);
    memcpy(key->comp_privkey[idx_qkd], qkd_ctx->key, QKD_KEY_SIZE);
#endif

#if !defined(NDEBUG) && defined(DEBUG_QKD)
    printf("Generated Key ID first bytes: ");
    for (size_t i = 0; i < 16 && i < QKD_KSID_SIZE; i++) {
        printf("%02x", qkd_ctx->key_id[i]);
    }
    printf("\n");
#endif

    QKD_DEBUG("Successfully generated QKD key material");
    return OQS_SUCCESS;

err:
    if (key->comp_privkey[idx_qkd]) {
        OPENSSL_secure_clear_free(key->comp_privkey[idx_qkd], QKD_KEY_SIZE);
        key->comp_privkey[idx_qkd] = NULL;
    }
    if (key->comp_pubkey[idx_qkd]) {
        OPENSSL_free(key->comp_pubkey[idx_qkd]);
        key->comp_pubkey[idx_qkd] = NULL;
    }
    return ret;
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of
 * pubkey/privkey buffers; returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY *oqsx_key_gen_evp_key_sig(OQSX_EVP_CTX *ctx,
                                          unsigned char *pubkey,
                                          unsigned char *privkey, int encode) {
    int ret = 0, ret2 = 0, aux = 0;

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;

    size_t pubkeylen = 0, privkeylen = 0;

    if (encode) { // hybrid
        aux = SIZE_OF_UINT32;
    }

    if (ctx->keyParam)
        kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
        kgctx = EVP_PKEY_CTX_new_id(ctx->evp_info->nid, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    if (ctx->evp_info->keytype == EVP_PKEY_RSA) {
        if (ctx->evp_info->length_public_key > 270) {
            ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 3072);
        } else {
            ret2 = EVP_PKEY_CTX_set_rsa_keygen_bits(kgctx, 2048);
        }
        ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);
    }

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        if (ctx->evp_info->nid != NID_ED25519 &&
            ctx->evp_info->nid != NID_ED448) {
            pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
            ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key ||
                                !pubkey_encoded,
                            ret, -3, errhyb);
            memcpy(pubkey + aux, pubkey_encoded, pubkeylen);
        } else {
            pubkeylen = ctx->evp_info->length_public_key;
            ret2 = EVP_PKEY_get_raw_public_key(pkey, pubkey + aux, &pubkeylen);
            ON_ERR_SET_GOTO(ret2 <= 0 ||
                                pubkeylen != ctx->evp_info->length_public_key,
                            ret, -3, errhyb);
        }
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey + aux, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0 ||
                            privkeylen != ctx->evp_info->length_private_key,
                        ret, -4, errhyb);
    } else {
        unsigned char *pubkey_enc = pubkey + aux;
        const unsigned char *pubkey_enc2 = pubkey + aux;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(!pubkey_enc ||
                            pubkeylen > (int)ctx->evp_info->length_public_key,
                        ret, -11, errhyb);
        unsigned char *privkey_enc = privkey + aux;
        const unsigned char *privkey_enc2 = privkey + aux;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(!privkey_enc ||
                            privkeylen > (int)ctx->evp_info->length_private_key,
                        ret, -12, errhyb);
        // selftest:
        EVP_PKEY *ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL,
                                       &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
        EVP_PKEY_free(ck2);
    }
    if (encode) {
        ENCODE_UINT32(pubkey, pubkeylen);
        ENCODE_UINT32(privkey, privkeylen);
    }
    OQS_KEY_PRINTF3(
        "OQSKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n",
        privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* Generate classic keys, store length in leading SIZE_OF_UINT32 bytes of
 * pubkey/privkey buffers; returned EVP_PKEY must be freed if not used
 */
static EVP_PKEY *oqsx_key_gen_evp_key_kem(OQSX_KEY *key, unsigned char *pubkey,
                                          unsigned char *privkey, int encode) {
    int ret = 0, ret2 = 0, aux = 0;

    QKD_DEBUG("oqsx_key_gen_evp_key_kem()");

    // Free at errhyb:
    EVP_PKEY_CTX *kgctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *pubkey_encoded = NULL;
    int idx_classic;
    OQSX_EVP_CTX *ctx = key->oqsx_provider_ctx.oqsx_evp_ctx;

    size_t pubkeylen = 0, privkeylen = 0;

    unsigned char *pubkey_sizeenc = key->pubkey;
    unsigned char *privkey_sizeenc = key->privkey;

    if (ctx->keyParam)
        kgctx = EVP_PKEY_CTX_new(ctx->keyParam, NULL);
    else
        kgctx = EVP_PKEY_CTX_new_id(ctx->evp_info->nid, NULL);
    ON_ERR_SET_GOTO(!kgctx, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen_init(kgctx);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -1, errhyb);

    ret2 = EVP_PKEY_keygen(kgctx, &pkey);
    ON_ERR_SET_GOTO(ret2 <= 0, ret, -2, errhyb);

    if (ctx->evp_info->raw_key_support) {
        // TODO: If available, use preallocated memory
        if (ctx->evp_info->nid != NID_ED25519 &&
            ctx->evp_info->nid != NID_ED448) {
            pubkeylen = EVP_PKEY_get1_encoded_public_key(pkey, &pubkey_encoded);
            ON_ERR_SET_GOTO(pubkeylen != ctx->evp_info->length_public_key ||
                                !pubkey_encoded,
                            ret, -3, errhyb);
            memcpy(pubkey + aux, pubkey_encoded, pubkeylen);
        } else {
            pubkeylen = ctx->evp_info->length_public_key;
            ret2 = EVP_PKEY_get_raw_public_key(pkey, pubkey + aux, &pubkeylen);
            ON_ERR_SET_GOTO(ret2 <= 0 ||
                                pubkeylen != ctx->evp_info->length_public_key,
                            ret, -3, errhyb);
        }
        privkeylen = ctx->evp_info->length_private_key;
        ret2 = EVP_PKEY_get_raw_private_key(pkey, privkey + aux, &privkeylen);
        ON_ERR_SET_GOTO(ret2 <= 0 ||
                            privkeylen != ctx->evp_info->length_private_key,
                        ret, -4, errhyb);
    } else {
        unsigned char *pubkey_enc = pubkey + aux;
        const unsigned char *pubkey_enc2 = pubkey + aux;
        pubkeylen = i2d_PublicKey(pkey, &pubkey_enc);
        ON_ERR_SET_GOTO(!pubkey_enc ||
                            pubkeylen > (int)ctx->evp_info->length_public_key,
                        ret, -11, errhyb);
        unsigned char *privkey_enc = privkey + aux;
        const unsigned char *privkey_enc2 = privkey + aux;
        privkeylen = i2d_PrivateKey(pkey, &privkey_enc);
        ON_ERR_SET_GOTO(!privkey_enc ||
                            privkeylen > (int)ctx->evp_info->length_private_key,
                        ret, -12, errhyb);
        // selftest:
        EVP_PKEY *ck2 = d2i_PrivateKey(ctx->evp_info->keytype, NULL,
                                       &privkey_enc2, privkeylen);
        ON_ERR_SET_GOTO(!ck2, ret, -14, errhyb);
        EVP_PKEY_free(ck2);
    }
    if (encode) {
        ENCODE_UINT32(pubkey_sizeenc, pubkeylen);
        ENCODE_UINT32(privkey_sizeenc, privkeylen);
    }
    OQS_KEY_PRINTF3(
        "OQSKM: Storing classical privkeylen: %ld & pubkeylen: %ld\n",
        privkeylen, pubkeylen);

    EVP_PKEY_CTX_free(kgctx);
    OPENSSL_free(pubkey_encoded);
    return pkey;

errhyb:
    EVP_PKEY_CTX_free(kgctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pubkey_encoded);
    return NULL;
}

/* allocates OQS and classical keys */
int oqsx_key_gen(OQSX_KEY *key) {
    int ret = 0;
    EVP_PKEY *pkey = NULL;

    QKD_DEBUG("oqsx_key_gen()");

    if (key->privkey == NULL || key->pubkey == NULL) {
        ret = oqsx_key_allocate_keymaterial(key, 0) ||
              oqsx_key_allocate_keymaterial(key, 1);
        ON_ERR_GOTO(ret, err_gen);
    }

    if (key->keytype == KEY_TYPE_KEM) {
        ret = !oqsx_key_set_composites(key, 0);
        ON_ERR_GOTO(ret, err_gen);
        ret = oqsx_key_gen_oqs(key, 1);
    } else if (key->keytype == KEY_TYPE_HYB_SIG) {
        pkey = oqsx_key_gen_evp_key_sig(key->oqsx_provider_ctx.oqsx_evp_ctx,
                                        key->pubkey, key->privkey, 1);
        ON_ERR_GOTO(pkey == NULL, err_gen);
        ret = !oqsx_key_set_composites(key, 0);
        ON_ERR_GOTO(ret, err_gen);
        OQS_KEY_PRINTF3("OQSKM: OQSX_KEY privkeylen %ld & pubkeylen: %ld\n",
                        key->privkeylen, key->pubkeylen);

        key->classical_pkey = pkey;
        ret = oqsx_key_gen_oqs(key, key->keytype != KEY_TYPE_HYB_SIG);
    } else if (key->keytype == KEY_TYPE_ECP_HYB_KEM ||
               key->keytype == KEY_TYPE_ECX_HYB_KEM) {
        int idx_classic;
        oqsx_comp_set_idx(key, &idx_classic, NULL, NULL);

        ret = !oqsx_key_set_composites(key, 1);
        ON_ERR_GOTO(ret != 0, err_gen);

        pkey = oqsx_key_gen_evp_key_kem(key, key->comp_pubkey[idx_classic],
                                        key->comp_privkey[idx_classic], 1);
        ON_ERR_GOTO(pkey == NULL, err_gen);

        OQS_KEY_PRINTF3("OQSKM: OQSX_KEY privkeylen %ld & pubkeylen: %ld\n",
                        key->privkeylen, key->pubkeylen);

        key->classical_pkey = pkey;
        ret = oqsx_key_gen_oqs(key, key->keytype != KEY_TYPE_HYB_SIG);
    } else if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
        int idx_classic = -1, idx_pq = -1, idx_qkd = -1;
        if (key->numkeys != 2) {
            QKD_DEBUG("oqsx_key_gen(): QKD_HYB_KEM with numkeys != 2 not "
                      "implemented");
            ret = 1;
            goto err_gen;
        }
        oqsx_comp_set_idx(key, NULL, &idx_pq, &idx_qkd);
        ret = !oqsx_key_set_composites(key, 1);
        ON_ERR_GOTO(ret != 0, err_gen);

        // First generate PQ keypair - this generates both public and private keys
        ret = oqsx_key_gen_oqs(key, 1); 
        ON_ERR_GOTO(ret != OQS_SUCCESS, err_gen);

        // Then initialize QKD component:
        // - For ETSI 004: Get only key ID via OPEN_CONNECT (actual key retrieved during decaps)
        // - For ETSI 014: Get both key ID and key via GET_KEY
        ret = oqsx_key_gen_qkd(key);
        ON_ERR_GOTO(ret != OQS_SUCCESS, err_gen);

        OQS_KEY_PRINTF3("OQSKM: OQSX_KEY privkeylen %ld & pubkeylen: %ld\n",
                    key->privkeylen, key->pubkeylen);
    } else if (key->keytype == KEY_TYPE_CMP_SIG) {
        int i;
        ret = oqsx_key_set_composites(key, 0);
        for (i = 0; i < key->numkeys; i++) {
            char *name;
            if ((name = get_cmpname(OBJ_sn2nid(key->tls_name), i)) == NULL) {
                ON_ERR_GOTO(ret, err_gen);
            }
            if (get_oqsname_fromtls(name) == 0) {
                pkey = oqsx_key_gen_evp_key_sig(
                    key->oqsx_provider_ctx.oqsx_evp_ctx, key->comp_pubkey[i],
                    key->comp_privkey[i], 0);
                OPENSSL_free(name);
                ON_ERR_GOTO(pkey == NULL, err_gen);
                key->classical_pkey = pkey;
            } else {
                ret =
                    OQS_SIG_keypair(key->oqsx_provider_ctx.oqsx_qs_ctx.sig,
                                    key->comp_pubkey[i], key->comp_privkey[i]);
                OPENSSL_free(name);
                ON_ERR_GOTO(ret, err_gen);
            }
        }
    } else {
        ret = 1;
    }
err_gen:
    if (ret) {
        EVP_PKEY_free(pkey);
        key->classical_pkey = NULL;
    }
    return ret;
}

int oqsx_key_secbits(OQSX_KEY *key) { return key->bit_security; }

int oqsx_key_maxsize(OQSX_KEY *key) {
    switch (key->keytype) {
    case KEY_TYPE_KEM:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_ECP_HYB_KEM:
    case KEY_TYPE_ECX_HYB_KEM:
        return key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info
                   ->kex_length_secret +
               key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret;
    case KEY_TYPE_QKD_HYB_KEM:
        // TODO_QKD: implement proper key handling here, triple hybrid as well
        return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret +
               QKD_KEY_SIZE;
    case KEY_TYPE_HYB_SIG:
        return key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature +
               key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->length_signature +
               SIZE_OF_UINT32;
    case KEY_TYPE_CMP_SIG:
        return sizeof(CompositeSignature) +
               key->oqsx_provider_ctx.oqsx_evp_ctx->evp_info->length_signature +
               key->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_signature;

    default:
        OQS_KEY_PRINTF("OQSX KEY: Wrong key type\n");
        return 0;
    }
}

int oqsx_key_get_oqs_public_key_len(OQSX_KEY *k) {
    switch (k->keytype) {
    case KEY_TYPE_KEM:
        return k->pubkeylen;
    case KEY_TYPE_HYB_SIG:
        return k->oqsx_provider_ctx.oqsx_qs_ctx.sig->length_public_key;
    case KEY_TYPE_ECX_HYB_KEM:
    case KEY_TYPE_ECP_HYB_KEM:
    case KEY_TYPE_QKD_HYB_KEM:
        return k->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        k->keytype);
        return -1;
    }
}
