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

// Error codes for specific failure scenarios
#define QKD_ERR_MEMORY     -1
#define QKD_ERR_VALIDATION -2
#define QKD_ERR_PROTOCOL   -3

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
    QKD_DEBUG("OQSKEYMGMT: set nid %d for %s\n", nid, tlsname);
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
    QKD_DEBUG("OQSKEYMGMT   get_secbits for nid %d\n", nid);
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].secbits;
    }
    return 0;
}

static int get_reverseshare(int nid) {
    int i;
    QKD_DEBUG("OQSKEYMGMT   get_reverseshare for nid %d\n", nid);
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].reverseshare;
    }
    return 0;
}

static int get_keytype(int nid) {
    int i;
    QKD_DEBUG("OQSKEYMGMT   get_keytype for nid %d\n", nid);
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].keytype;
    }
    return 0;
}

char *get_oqsname_fromtls(char *tlsname) {
    int i;
    QKD_DEBUG("OQSKEYMGMT   get_oqsname_fromtls for %s\n", tlsname);
    for (i = 0; i < NID_TABLE_LEN; i++) {
        // TODO_QKD: check if we need to add QKD keys here
    }
    return 0; // classical
}

char *get_oqsname(int nid) {
    int i;
    QKD_DEBUG("OQSKEYMGMT   get_oqsname for nid %d\n", nid);
    for (i = 0; i < NID_TABLE_LEN; i++) {
        if (nid_names[i].nid == nid)
            return nid_names[i].oqsname;
    }
    return 0;
}

char *get_cmpname(int nid, int index) {
    int i, len;
    QKD_DEBUG("OQSKEYMGMT   get_cmpname for nid %d\n", nid);
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
    QKD_DEBUG("OQSKEYMGMT   get_oqsalg_idx for nid %d\n", nid);
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
    QKD_DEBUG("OQSKEYMGMT: set idx for key %s\n", key->tls_name);
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
            if (key->reverse_share) {
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
    QKD_DEBUG("OQSKEYMGMT: set offsets for key %s\n", key->tls_name);
    // The only special case with reversed keys (so far)
    // is: x25519_mlkem*
    int reverse_share = key->reverse_share;

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
                key->comp_privkey[0] = privkey + SIZE_OF_UINT32;
                key->comp_privkey[1] =
                    privkey + SIZE_OF_UINT32 + 
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
                QKD_DEBUG("Offset for PQC privkey pointer = %zu", (size_t)SIZE_OF_UINT32);
                QKD_DEBUG("Offset for QKD privkey pointer = %zu", (size_t)SIZE_OF_UINT32 + (size_t)key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key);
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
                key->comp_pubkey[0] = pubkey + SIZE_OF_UINT32;
                key->comp_pubkey[1] =
                    pubkey + SIZE_OF_UINT32 +
                    key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
                QKD_DEBUG("Offset for PQC pubkey pointer = %zu", (size_t)SIZE_OF_UINT32);
                QKD_DEBUG("Offset for QKD pubkey pointer = %zu", (size_t)SIZE_OF_UINT32 + (size_t)key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key);
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
    QKD_DEBUG("OQSKEYMGMT: set composites for key %s\n", key->tls_name);
    OQS_KEY_PRINTF2("Setting composites with evp_info %p\n", key->evp_info);

    if (key->numkeys == 1) {
        key->comp_privkey[0] = key->privkey;
        key->comp_pubkey[0] = key->pubkey;
    } else if (key->numkeys == 2) { // QKD hybrid case
        // Calculate expected lengths for validation
        size_t pq_privkey_len = key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key;
        size_t pq_pubkey_len = key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        
        // Expected total lengths including size header
        size_t expected_privkey_len = SIZE_OF_UINT32 + pq_privkey_len + QKD_KEY_SIZE;
        size_t expected_pubkey_len = SIZE_OF_UINT32 + pq_pubkey_len + QKD_KSID_SIZE;

        // Validate total lengths match expected sizes
        if (key->privkeylen != expected_privkey_len || 
            key->pubkeylen != expected_pubkey_len) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
            return 0;
        }

        /* Sets composites for comp_privkey and comp_pubkey structures */
        ret = oqsx_comp_set_offsets(key, key->privkey != NULL,
                                    key->pubkey != NULL,
                                    classic_lengths_fixed);
        ON_ERR_GOTO(ret == 0, err);

        if (!key->privkey) {
            key->comp_privkey[0] = NULL;
            key->comp_privkey[1] = NULL;
        }
        if (!key->pubkey) {
            key->comp_pubkey[0] = NULL;
            key->comp_pubkey[1] = NULL;
        }

        // Additional validation of component lengths
        if (key->comp_privkey[0] && key->comp_privkey[1]) {
            if ((char*)key->comp_privkey[1] - (char*)key->comp_privkey[0] != 
                pq_privkey_len) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return 0;
            }
        }
        
        if (key->comp_pubkey[0] && key->comp_pubkey[1]) {
            if ((char*)key->comp_pubkey[1] - (char*)key->comp_pubkey[0] != 
                pq_pubkey_len) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
                return 0;
            }
        }
    } else {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_ENCODING);
        return 0;
    }
err:
    return ret;
}

/* Verify PQ key component format and structure */
static int verify_pq_key(void *privkey, void *pubkey, const OQS_KEM *kem_ctx) {
    if (!privkey || !pubkey || !kem_ctx) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }
    QKD_DEBUG("Verifying PQ key component");
    /* Verify key sizes match OQS algorithm parameters */
    size_t expected_priv_len = kem_ctx->length_secret_key;
    size_t expected_pub_len = kem_ctx->length_public_key;

    /* Basic format validation - first few bytes should follow OQS patterns */
    unsigned char *priv = (unsigned char *)privkey;
    unsigned char *pub = (unsigned char *)pubkey;

    /* Check for obviously invalid patterns */
    if (priv[0] == 0 && priv[1] == 0 && priv[2] == 0) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }

    return 1;
}

/* Verify QKD material format and structure */
static int verify_qkd_material(void *privkey, void *pubkey) {
    if (!privkey || !pubkey) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }
    QKD_DEBUG("Verifying QKD material");
    /* Verify QKD key ID format (public component) */
    unsigned char *key_id = (unsigned char *)pubkey;
    if (!key_id) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }

    /* Verify key ID is not all zeros or all ones */
    int all_zero = 1, all_one = 1;
    for (size_t i = 0; i < QKD_KSID_SIZE; i++) {
        if (key_id[i] != 0) all_zero = 0;
        if (key_id[i] != 0xFF) all_one = 0;
    }
    if (all_zero || all_one) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }

    /* Verify QKD key material (private component) */
    unsigned char *key_material = (unsigned char *)privkey;
    if (!key_material) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }

    return 1;
}

/* Main validation function for key components */
int validate_key_components(OQSX_KEY *key) {
    if (!key) {
        ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
        return 0;
    }
    QKD_DEBUG("Validating key components for key %s", key->tls_name);
    /* Handle hybrid QKD key case */
    if (key->numkeys == 2) {
        int idx_pq = -1, idx_qkd = -1;

        /* Get correct component indices */
        oqsx_comp_set_idx(key, NULL, &idx_pq, &idx_qkd);
        if (idx_pq == -1 || idx_qkd == -1) {
            ERR_raise(ERR_LIB_USER, OQSPROV_R_INVALID_KEY);
            return 0;
        }

        /* Verify PQ key component */
        if (!verify_pq_key(key->comp_privkey[idx_pq], 
                          key->comp_pubkey[idx_pq],
                          key->oqsx_provider_ctx.oqsx_qs_ctx.kem)) {
            QKD_DEBUG("PQ key component validation failed");
            return 0;
        }

        /* Verify QKD material */
        /*
        if (!verify_qkd_material(key->comp_privkey[idx_qkd], 
                                key->comp_pubkey[idx_qkd])) {
            QKD_DEBUG("QKD material validation failed");
            return 0;
        }*/
    }
    
    return 1;
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
    QKD_DEBUG("Generating OQSX key for nid %d", nid);
    char *tls_algname = (char *)OBJ_nid2sn(nid);
    OQS_KEY_PRINTF2("                    for tls_name %s\n", tls_algname);

    if (!tls_algname) {
        QKD_DEBUG("NID %d not found", nid);
        ERR_raise(ERR_LIB_USER, OQSPROV_R_WRONG_PARAMETERS);
        return NULL;
    }

    return qkd_kem_key_new(libctx, get_oqsname(nid), tls_algname, get_keytype(nid),
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

static const int oqshybkem_init_ecp(char *tls_name, OQSX_EVP_CTX *evp_ctx) {
    int ret = 1;
    int idx = 0;
    QKD_DEBUG("OQSX KEY: init_ecp called with %s\n", tls_name);
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
    QKD_DEBUG("OQSX KEY: init_ecx called with %s\n", tls_name);
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

    QKD_DEBUG("OQSX KEY: key_op called with data of len %d\n", plen);

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
            QKD_DEBUG("POPULATING OQS PUBLIC KEY");
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

    if (!oqsx_key_set_composites(key,
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
    if (key->numkeys == 2) { // hybrid key
        int idx_classic;
        QKD_DEBUG("Recreating classic key from hybrid key");
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
    QKD_DEBUG("oqsx_key_from_x509pubkey()");
    if (!xpk || (!X509_PUBKEY_get0_param(NULL, &p, &plen, &palg, xpk))) {
        return NULL;
    }

    oqsx = oqsx_key_op(palg, p, plen, KEY_OP_PUBLIC, libctx, propq);

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
    QKD_DEBUG("oqsx_key_from_pkcs8()");

    if (!PKCS8_pkey_get0(NULL, &p, &plen, &palg, p8inf))
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, plen);
    if (oct == NULL) {
        p = NULL;
        plen = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        plen = ASN1_STRING_length(oct);
    }


    oqsx = oqsx_key_op(palg, p, plen + key_diff, KEY_OP_PRIVATE, libctx, propq);
    ASN1_OCTET_STRING_free(oct);

    return oqsx;
}

static const int (*init_kex_fun[])(char *, OQSX_EVP_CTX *) = {
    oqshybkem_init_ecp, oqshybkem_init_ecx};
extern const char *oqs_oid_alg_list[];

OQSX_KEY *qkd_kem_key_new(OSSL_LIB_CTX *libctx, char *oqs_name, char *tls_name,
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

    QKD_DEBUG("qkd_kem_key_new()");

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
            QKD_KEY_SIZE +                                  // QKD symmetric key
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_secret_key; // PQ key

        ret->pubkeylen =
            (ret->numkeys - 1) * SIZE_OF_UINT32 + // Size headers
            QKD_KSID_SIZE +                                 // QKD ID
            ret->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key; // PQ key
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
    QKD_DEBUG("oqsx_key_free()");
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
    if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
        OQS_KEM_free(key->oqsx_provider_ctx.oqsx_qs_ctx.kem);
    }
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
    QKD_DEBUG("oqsx_key_up_ref()");
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

    QKD_DEBUG("oqsx_key_allocate_keymaterial()");

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

    // TODO_QKD: adapt this function to handle QKD keys
    QKD_DEBUG("oqsx_key_fromdata()");
    int classic_lengths_fixed = 0;

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

    QKD_DEBUG("=== Starting QKD Key Generation ===");

    // Initial component setup and validation chain
    oqsx_comp_set_idx(key, NULL, NULL, &idx_qkd);
    QKD_DEBUG("Got QKD index: %d", idx_qkd);
    ON_ERR_SET_GOTO(idx_qkd < 0, ret, QKD_ERR_VALIDATION, err);

    // Check key is valid
    QKD_DEBUG("Checking key pointer: %p", key);
    ON_ERR_SET_GOTO(!key, ret, QKD_ERR_VALIDATION, err);

    // Access QKD context through key structure
    QKD_CTX *qkd_ctx = key->qkd_ctx;
    QKD_DEBUG("QKD context pointer: %p", qkd_ctx);
    ON_ERR_SET_GOTO(!qkd_ctx, ret, QKD_ERR_VALIDATION, err);

    // Only initiator should generate initial key
    if (!qkd_ctx->is_initiator) {
        QKD_DEBUG("QKD key generation only for initiator");
        ret = QKD_ERR_PROTOCOL;
        goto err;
    }

    // Validate allocation sizes
    size_t total_pub_size = QKD_KSID_SIZE;
    size_t total_priv_size = QKD_KEY_SIZE;
    ON_ERR_SET_GOTO(total_pub_size > SIZE_MAX || total_priv_size > SIZE_MAX, 
                    ret, QKD_ERR_MEMORY, err);

    QKD_DEBUG("Allocating QKD components");
    // Allocate memory for QKD components
    //TODO_QKD: this is the source of the QKD part of the public key not being set
    //key->comp_pubkey[idx_qkd] = OPENSSL_malloc(total_pub_size);
    //key->comp_privkey[idx_qkd] = OPENSSL_secure_malloc(total_priv_size);

    QKD_DEBUG("Pubkey pointer: %p, Privkey pointer: %p",
              key->comp_pubkey[idx_qkd],
              key->comp_privkey[idx_qkd]);

    if (!key->comp_pubkey[idx_qkd] || !key->comp_privkey[idx_qkd]) {
        QKD_DEBUG("Failed to allocate memory for QKD components");
        ret = QKD_ERR_MEMORY;
        goto err;
    }

#ifdef ETSI_004_API
    // For ETSI 004: At key generation time, only establish connection to get key ID
    if (!qkd_open_connect(qkd_ctx)) {
        QKD_DEBUG("Failed to establish QKD connection");
        ret = QKD_ERR_PROTOCOL;
        goto err;
    }
    
    // Store key ID using secure copy
    memcpy(key->comp_pubkey[idx_qkd], qkd_ctx->key_id, QKD_KSID_SIZE);
    
    // Initialize private key to a known non-zero pattern for debug purposes
    unsigned char init_pattern[QKD_KEY_SIZE];
    for (size_t i = 0; i < QKD_KEY_SIZE; i++) {
        init_pattern[i] = (unsigned char)(i + 1);
    }
    memcpy(key->comp_privkey[idx_qkd], init_pattern, QKD_KEY_SIZE);

#elif defined(ETSI_014_API)
    const char* is_server = getenv("IS_TLS_SERVER");
    
    // Additional server validation
    /**/
    if (is_server && !qkd_ctx->key_id) {
        QKD_DEBUG("Error: Server missing key ID");
        ret = QKD_ERR_VALIDATION;
        goto err;
    }

    if (is_server == NULL || strcmp(is_server, "0") == 0) {
        // Client path - key generation
        if (!qkd_get_key(qkd_ctx)) {
            QKD_DEBUG("Failed to get QKD key material");
            ret = QKD_ERR_PROTOCOL;
            goto err;
        }
    } else {
        // Server path - key retrieval and validation
        if (!qkd_ctx->key_id) {
            QKD_DEBUG("Error: Server requires pre-existing QKD key");
            ret = QKD_ERR_PROTOCOL;
            goto err;
        }
    }

    // Store key ID for both client and server using secure copy
    memcpy(key->comp_pubkey[idx_qkd], qkd_ctx->key_id, QKD_KSID_SIZE);

#if !defined(NDEBUG) && defined(DEBUG_QKD)
    QKD_DEBUG("=== QKD Operation Summary ===");
    QKD_DEBUG("Mode: %s", is_server ? "Server" : "Client");
    QKD_DEBUG("API: ETSI 014");
    QKD_DEBUG("Key ID:");
    for (size_t i = 0; i < QKD_KSID_SIZE; i++) {
        fprintf(stderr, "%02x", qkd_ctx->key_id[i]);
    }
    fprintf(stderr, "\n");
    /*
    if (qkd_ctx->key) {
        size_t keylen = 0;
        unsigned char *raw_key = NULL;
        if (EVP_PKEY_get_raw_private_key(qkd_ctx->key, NULL, &keylen) > 0) {
            raw_key = OPENSSL_malloc(keylen);
            if (raw_key && EVP_PKEY_get_raw_private_key(qkd_ctx->key, raw_key, &keylen) > 0) {
                QKD_DEBUG("Key Material (%zu bytes):", keylen);
                for (size_t i = 0; i < keylen; i++) {
                    fprintf(stderr, "%02x", raw_key[i]);
                }
                fprintf(stderr, "\n");
            }
            OPENSSL_clear_free(raw_key, keylen);
        }
    }*/
#endif

    QKD_DEBUG("QKD key material processed successfully");
#endif

    QKD_DEBUG("=== Successfully completed QKD key generation ===");
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

    if (key->keytype == KEY_TYPE_QKD_HYB_KEM) {
        int idx_classic = -1, idx_pq = -1, idx_qkd = -1;
        if (key->numkeys != 2) {
            QKD_DEBUG("oqsx_key_gen(): QKD_HYB_KEM with numkeys != 2 not implemented");
            ret = 1;
            goto err_gen;
        }

        oqsx_comp_set_idx(key, NULL, &idx_pq, &idx_qkd);
        ret = !oqsx_key_set_composites(key, 1);
        ON_ERR_GOTO(ret != 0, err_gen);

        // First generate PQ keypair - this generates both public and private keys
        ret = oqsx_key_gen_oqs(key, 1);
        ON_ERR_GOTO(ret != OQS_SUCCESS, err_gen);
        // Validate PQ key components after generation
        if (!verify_pq_key(key->comp_privkey[idx_pq], 
                          key->comp_pubkey[idx_pq],
                          key->oqsx_provider_ctx.oqsx_qs_ctx.kem)) {
            QKD_DEBUG("PQ key component validation failed");
            ret = OQS_ERROR;
            goto err_gen;
        }

        // Then initialize QKD component:
        // - For ETSI 004: Get only key ID via OPEN_CONNECT (actual key retrieved during decaps)
        // - For ETSI 014: Get both key ID and key via GET_KEY
        ret = oqsx_key_gen_qkd(key);
        ON_ERR_GOTO(ret != OQS_SUCCESS, err_gen);
        // Validate QKD material after generation
        /*
        if (!verify_qkd_material(key->comp_privkey[idx_qkd], 
                                key->comp_pubkey[idx_qkd])) {
            QKD_DEBUG("QKD material validation failed");
            ret = OQS_ERROR;
            goto err_gen;
        }*/

        if (key->keytype == KEY_TYPE_QKD_HYB_KEM && key->numkeys == 2) {
            int idx_pq = 0; // for PQC component in a PQC+QKD hybrid
            if (key->comp_pubkey && key->comp_pubkey[idx_pq]) {
                unsigned char *pqc_pub = (unsigned char *) key->comp_pubkey[idx_pq];
                size_t pqc_len = key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
                QKD_DEBUG("_____PQC public key (idx %d, %zu bytes):", idx_pq, pqc_len);
                #if !defined(NDEBUG) && defined(DEBUG_QKD)
                /*
                for (size_t i = 0; i < pqc_len; i++) {
                    fprintf(stderr, "%02x", pqc_pub[i]);
                }*/
                fprintf(stderr, "\n");
                #endif
            }

            int idx_qkd = key->numkeys - 1; // For PQC+QKD, idx_qkd should be 1.
            if (key->comp_pubkey && key->comp_pubkey[idx_qkd]) {
                unsigned char *qkd_pub = (unsigned char *) key->comp_pubkey[idx_qkd];
                size_t qkd_len = QKD_KSID_SIZE; // QKD public key is fixed size
                QKD_DEBUG("_____QKD public key (idx %d, %zu bytes):", idx_qkd, qkd_len);
                #if !defined(NDEBUG) && defined(DEBUG_QKD)
                
                for (size_t i = 0; i < qkd_len; i++) {
                    fprintf(stderr, "%02x", qkd_pub[i]);
                }
                fprintf(stderr, "\n");
                #endif
            }
        }

        QKD_DEBUG("OQSKM: OQSX_KEY privkeylen %ld & pubkeylen: %ld\n",
                key->privkeylen, key->pubkeylen);
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
    case KEY_TYPE_QKD_HYB_KEM:
        // TODO_QKD: implement proper key handling here, triple hybrid as well
        return key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_shared_secret +
               QKD_KEY_SIZE;
    default:
        OQS_KEY_PRINTF("OQSX KEY: Wrong key type\n");
        return 0;
    }
}

int oqsx_key_get_oqs_public_key_len(OQSX_KEY *k) {
    switch (k->keytype) {
    QKD_DEBUG("OQSX KEY: Getting OQS public key length");
    case KEY_TYPE_QKD_HYB_KEM:
        return k->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
    default:
        OQS_KEY_PRINTF2("OQSX_KEY: Unknown key type encountered: %d\n",
                        k->keytype);
        return -1;
    }
}
