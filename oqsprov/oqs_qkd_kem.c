/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_kem.c
 */

#include "oqs_qkd_kem.h"
#include <qkd-etsi-api/api.h>

static OSSL_FUNC_kem_newctx_fn oqs_qkd_kem_newctx;
static OSSL_FUNC_kem_encapsulate_fn oqs_qkd_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_qkd_kem_decaps;
static OSSL_FUNC_kem_freectx_fn oqs_qkd_kem_freectx;

#define DEBUG_QKD

#ifdef NDEBUG
#define QKD_DEBUG(fmt, ...)
#else
    #ifdef DEBUG_QKD
    #define QKD_DEBUG(fmt, ...) \
        fprintf(stderr, "QKD DEBUG: %s:%d: " fmt "\n", __func__, __LINE__, ##__VA_ARGS__)
    #else
    #define QKD_DEBUG(fmt, ...)
    #endif
#endif

static int init_qkd_context(OQSX_KEY *oqsx_key, bool is_initiator) {
    int ret = OQS_SUCCESS;
    QKD_DEBUG("Initializing QKD context");

    // Return success if context already exists and role matches
    if (oqsx_key->qkd_ctx != NULL) {
        // TODO_QKD: check if we should set key_id to 0 if is_initiator
        if (is_initiator) {
            memset(oqsx_key->qkd_ctx->key_id, 0, QKD_KSID_SIZE);
        }
        if (oqsx_key->qkd_ctx->is_initiator == is_initiator) {
            QKD_DEBUG("QKD context already initialized with correct role");
            return OQS_SUCCESS;
        }
        // Close existing context if role mismatch
        qkd_close(oqsx_key->qkd_ctx);
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
    }

    // Allocate new context
    oqsx_key->qkd_ctx = OPENSSL_malloc(sizeof(QKD_CTX));
    ON_ERR_SET_GOTO(oqsx_key->qkd_ctx == NULL, ret, OQS_ERROR, err);

    // Initialize context with clean state
    memset(oqsx_key->qkd_ctx, 0, sizeof(QKD_CTX));
    oqsx_key->qkd_ctx->is_initiator = is_initiator;
    if (is_initiator) {
        memset(oqsx_key->qkd_ctx->key_id, 0, QKD_KSID_SIZE);
    }
    // Open QKD connection
    ret = qkd_open(oqsx_key->qkd_ctx);
    if (ret <= 0) {
        QKD_DEBUG("Failed to open QKD connection");
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        goto err;
    }

    QKD_DEBUG("QKD context initialized successfully as %s", 
              is_initiator ? "initiator" : "responder");
err:
    return ret;
}

static void oqsx_comp_set_idx(const OQSX_KEY *key, int *idx_classic,
                              int *idx_pq, int *idx_qkd) {
    //TODO_QKD: put in a shared file with oqs_kmgmt.c and oqsprov_keys.c
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
                *idx_classic = -1;  // No classical component
            if (idx_pq)
                *idx_pq = 0;        // PQ at index 0, QKD at index 1
        //TODO_QKD: implement the triple hybrid case
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
            *idx_qkd = -1;  // No QKD component
    }
}

static void *oqs_qkd_kem_newctx(void *provctx) {
    PROV_OQSKEM_CTX *qkdkemctx = OPENSSL_zalloc(sizeof(PROV_OQSKEM_CTX));

    QKD_DEBUG("oqs_qkd_kem_newctx(): OQS KEM provider called: newctx\n");
    
    if (qkdkemctx == NULL)
        return NULL;

    qkdkemctx->libctx = PROV_OQS_LIBCTX_OF(provctx);

    // TODO_QKD: Initialize QKD connection???

    return qkdkemctx;
}

static void oqs_qkd_kem_freectx(void *vpkemctx) {
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    if (qkdkemctx && qkdkemctx->kem && qkdkemctx->kem->qkd_ctx) {
        // Close QKD connection with direct pointer
        qkd_close(qkdkemctx->kem->qkd_ctx);
        oqsx_key_free(qkdkemctx->kem);
        OPENSSL_free(qkdkemctx);
    }
    QKD_DEBUG("oqs_qkd_kem_freectx(): OQS KEM context freed");
}

static int oqs_qkd_get_key_material(QKD_CTX *ctx, 
                                   const unsigned char *key_id_in,
                                   unsigned char *key_id_out,
                                   unsigned char *key_out) {
    int ret = OQS_SUCCESS;
    unsigned char *key_bytes = NULL;
    size_t key_len = 0;

    QKD_DEBUG("Getting QKD key material");

    ON_ERR_SET_GOTO(!ctx || !key_out, ret, OQS_ERROR, err);

    if (ctx->is_initiator) {
        ON_ERR_SET_GOTO(key_id_in != NULL, ret, OQS_ERROR, err);
        ON_ERR_SET_GOTO(key_id_out == NULL, ret, OQS_ERROR, err);
        if (!qkd_get_key(ctx)) {
            ret = OQS_ERROR;
            goto err;
        }
        memcpy(key_id_out, ctx->key_id, QKD_KSID_SIZE);
    } else {
        ON_ERR_SET_GOTO(key_id_in == NULL, ret, OQS_ERROR, err);
        ON_ERR_SET_GOTO(key_id_out != NULL, ret, OQS_ERROR, err);

        memcpy(ctx->key_id, key_id_in, QKD_KSID_SIZE);
        if (!qkd_get_key(ctx)) {
            ret = OQS_ERROR;
            goto err;
        }
    }

    memcpy(key_out, ctx->key, QKD_KEY_SIZE);

#if !defined(NDEBUG) && defined(DEBUG_QKD)
    printf("Key Material: ");
    for (size_t i = 0; i < QKD_KEY_SIZE; i++) {
        printf("%02x", key_out[i]);
    }
    printf("\n");
#endif
    return 1; //TODO_QKD: Check return handling

err:
    QKD_DEBUG("QKD key material retrieval %s", ret == OQS_SUCCESS ? "succeeded" : "failed");
    if (key_bytes) {
        OPENSSL_clear_free(key_bytes, key_len);
    }
    return ret;
}

static int oqs_qkd_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct,
                                      size_t *ctlen, unsigned char *secret,
                                      size_t *secretlen, int keyslot) {
    //TODO_QKD: review this function
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem;

    // Validate KEM context
    ON_ERR_SET_GOTO(oqsx_key == NULL, ret, -1, err);

    // Set required lengths
    ON_ERR_SET_GOTO(ctlen == NULL, ret, -2, err);
    ON_ERR_SET_GOTO(secretlen == NULL, ret, -3, err);
    *ctlen = QKD_KSID_SIZE;
    *secretlen = QKD_KEY_SIZE;

    // If buffers are NULL, return lengths
    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("QKD KEM returning lengths %zu and %zu", *ctlen, *secretlen);
        return 1;
    }

    // Validate public key components
    ON_ERR_SET_GOTO(oqsx_key->comp_pubkey == NULL, ret, -4, err);
    ON_ERR_SET_GOTO(oqsx_key->comp_pubkey[keyslot] == NULL, ret, -5, err);

    ret = oqs_qkd_get_key_material(oqsx_key->qkd_ctx, NULL, ct, secret);
    ON_ERR_SET_GOTO(ret < 0, ret, -6, err);
    ret = 1; // TODO_QKD: Check return handling
err:
    //TODO_QKD: free resources if needed
    return ret;
}

static int oqs_qkd_kem_decaps_keyslot(void *vpkemctx, unsigned char *secret,
                                     size_t *secretlen,
                                     const unsigned char *ct, size_t ctlen,
                                     int keyslot) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem;

    QKD_DEBUG("OQS QKD KEM provider called: decaps_keyslot");

    // Validate KEM context
    ON_ERR_SET_GOTO(oqsx_key == NULL, ret, -1, err);
    // Validate length pointer
    ON_ERR_SET_GOTO(secretlen == NULL, ret, -2, err);

    // Set required secret length
    *secretlen = QKD_KEY_SIZE;

    // If secret buffer is NULL, just return required length
    if (secret == NULL) {
        return 1;
    }

    // Validate input parameters
    ON_ERR_SET_GOTO(ct == NULL, ret, -3, err);
    ON_ERR_SET_GOTO(ctlen != QKD_KSID_SIZE, ret, -4, err);

#if !defined(NDEBUG) && defined(DEBUG_QKD)
        printf("Key ID first bytes: ");
        for (size_t i = 0; i < 16 && i < QKD_KSID_SIZE; i++) {
            printf("%02x", ct[i]);
        }
        printf("\n");
#endif
    // Perform QKD decapsulation to retrieve shared secret using key_id
    ret = oqs_qkd_get_key_material(oqsx_key->qkd_ctx,
                                  ct,        // Input key_id
                                  NULL,      // No output key_id needed
                                  secret);   // Output buffer for secret
    ON_ERR_SET_GOTO(ret < 0, ret, -5, err);

    QKD_DEBUG("QKD KEM decapsulation succeeded");

err:
    // TODO_QKD: free resources if needed
    return ret;
}

/// QKD-KEM hybrid functions
int oqs_qkd_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                              unsigned char *secret, size_t *secretlen) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem; //TODO_QKD: this used to be a const
    size_t secretLenQKD = QKD_KEY_SIZE;
    size_t ctLenQKD = QKD_KSID_SIZE;
    size_t secretLenPQ = 0, ctLenPQ = 0;
    unsigned char *ctQKD, *ctPQ, *secretQKD, *secretPQ;

    QKD_DEBUG("QKD KEM encaps starting");

    // Retrieve keyslot indices
    int idx_pq = -1, idx_qkd = -1;
    oqsx_comp_set_idx(oqsx_key, NULL, &idx_pq, &idx_qkd);

    if (idx_pq && idx_qkd) {
            QKD_DEBUG("Error: Indices for classic, PQ, and QKD must be distinct.\n");
            goto err;
    }

    ON_ERR_SET_GOTO(idx_pq == -1 || idx_qkd == -1, ret, OQS_ERROR, err);

    ret = init_qkd_context(oqsx_key, true);  // Initialize as initiator
    ON_ERR_SET_GOTO(ret < 0, ret, OQS_ERROR, err);

    // Check for NULL public key components directly in qkdkemctx
    ON_ERR_SET_GOTO(oqsx_key->comp_pubkey == NULL, ret, OQS_ERROR, err);

    // Get QKD lengths
    ret = oqs_qkd_kem_encaps_keyslot(vpkemctx, NULL, &ctLenQKD, NULL, &secretLenQKD,
                                     idx_qkd);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    
    // Get PQ sizes
    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, NULL, &ctLenPQ, NULL, &secretLenPQ,
                                    idx_pq);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    
    // Set total sizes
    *ctlen = ctLenQKD + ctLenPQ;
    *secretlen = secretLenQKD + secretLenPQ;

    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("HYB KEM returning lengths %ld and %ld\n", *ctlen,
                        *secretlen);
        return 1;
    }

    /* Rule: if the classical algorithm is not FIPS approved
       but the PQ algorithm is: PQ share comes first
       otherwise: classical share comes first.
       QKD share is always last.
     */
    if (oqsx_key->numkeys == 2) {
        ctPQ = ct;
        ctQKD = ct + ctLenPQ;
        secretPQ = secret;
        secretQKD = secret + secretLenPQ;
    } else {
        // TODO_QKD: implement the triple hybrid case
        // raise error
        QKD_DEBUG("Error: Triple hybrid case not implemented yet.\n");
        goto err;
    }

    // Encapsulate QKD key
    ret = oqs_qkd_kem_encaps_keyslot(vpkemctx, ctQKD, &ctLenQKD, secretQKD, &secretLenQKD,
                                     idx_qkd);
    // print ret value
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    // Encapsulate PQ key
    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, ctPQ, &ctLenPQ, secretPQ, &secretLenPQ,
                                    idx_pq);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    QKD_DEBUG("QKD KEM encaps completed successfully");

err:
    QKD_DEBUG("QKD KEM encaps finishing with ret=%d", ret);
    return ret;
}

/* QKD: Have into account that if we don't have the classical part, we cannot
detect tampering and the return will be 1 from the PQ part */
int oqs_qkd_kem_decaps(void *vpkemctx, unsigned char *secret,
                       size_t *secretlen, const unsigned char *ct,
                       size_t ctlen) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem; //TODO_QKD: this used to be a const
    const OQS_KEM *qs_ctx = qkdkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    size_t secretLenQKD = QKD_KEY_SIZE;
    size_t ctLenQKD = QKD_KSID_SIZE;
    size_t secretLenPQ = 0, ctLenPQ = 0;
    const unsigned char *ctQKD, *ctPQ;
    unsigned char *secretQKD, *secretPQ;

    QKD_DEBUG("QKD KEM decaps starting");

    // Retrieve keyslot indices
    int idx_pq = -1, idx_qkd = -1;
    oqsx_comp_set_idx(oqsx_key, NULL, &idx_pq, &idx_qkd);
    ON_ERR_SET_GOTO(idx_pq == -1 || idx_qkd == -1, ret, OQS_ERROR, err);

    ret = init_qkd_context(oqsx_key, false);  // Initialize as responder
    ON_ERR_SET_GOTO(ret < 0, ret, OQS_ERROR, err);

    // Get QKD lengths
    ret = oqs_qkd_kem_decaps_keyslot(vpkemctx, NULL, &secretLenQKD, NULL, 0,
                                    idx_qkd);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);
    
    // Get PQ lengths
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLenPQ, NULL, 0,
                                   idx_pq);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    // Set total sizes
    *secretlen = secretLenQKD + secretLenPQ;

    if (secret == NULL) {
        return 1;
    }

    ctLenPQ = qs_ctx->length_ciphertext;
    ON_ERR_SET_GOTO(ctlen != (ctLenQKD + ctLenPQ), ret, OQS_ERROR, err);

    /* Rule: if the classical algorithm is not FIPS approved
       but the PQ algorithm is: PQ share comes first
       otherwise: classical share comes first.
       QKD share is always last.
     */
    if (oqsx_key->numkeys == 2) {
        ctPQ = ct;
        ctQKD = ct + ctLenPQ;
        secretPQ = secret;
        secretQKD = secret + secretLenPQ;
    } else {
        // TODO_QKD: implement the triple hybrid case
        // raise error
        QKD_DEBUG("Error: Triple hybrid case not implemented yet.\n");
        goto err;
    }

    // Perform QKD decapsulation
    ret = oqs_qkd_kem_decaps_keyslot(vpkemctx, secretQKD, &secretLenQKD,
                                    ctQKD, ctLenQKD, idx_qkd);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    // Perform PQ decapsulation
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, secretPQ, &secretLenPQ,
                                   ctPQ, ctLenPQ, idx_pq);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    QKD_DEBUG("QKD KEM decaps completed successfully");
err:
    return ret;
}