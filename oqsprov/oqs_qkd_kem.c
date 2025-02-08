/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_kem.c
 */
#include <openssl/err.h>
#include "oqs_qkd_kem.h"
#include <qkd-etsi-api/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api/etsi014/api.h>
#endif
#include "oqs_qkd_ctx.h"

static OSSL_FUNC_kem_newctx_fn oqs_qkd_kem_newctx;
static OSSL_FUNC_kem_encapsulate_fn oqs_qkd_kem_encaps;
static OSSL_FUNC_kem_decapsulate_fn oqs_qkd_kem_decaps;
static OSSL_FUNC_kem_freectx_fn oqs_qkd_kem_freectx;

#define DEBUG_QKD

#ifdef NDEBUG
#define QKD_DEBUG(fmt, ...)
#else
#ifdef DEBUG_QKD
#define QKD_DEBUG(fmt, ...)                                                    \
    fprintf(stderr, "QKD DEBUG: %s:%d: " fmt "\n", __func__, __LINE__,         \
            ##__VA_ARGS__)
#else
#define QKD_DEBUG(fmt, ...)
#endif
#endif

static void oqsx_comp_set_idx(const OQSX_KEY *key, int *idx_classic,
                              int *idx_pq, int *idx_qkd) {
    // TODO_QKD: put in a shared file with oqs_kmgmt.c and oqsprov_keys.c
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
#ifdef ETSI_004_API // TODO_QKD: check if we should do something for the ETSI_014_API case
        qkd_close(qkdkemctx->kem->qkd_ctx);
#endif
        
    }
    oqsx_key_free(qkdkemctx->kem);
    OPENSSL_free(qkdkemctx);
    QKD_DEBUG("oqs_qkd_kem_freectx(): OQS KEM context freed");
}

/* For key retrieval during encapsulation (Bob) */
static int oqs_qkd_get_encaps_key(QKD_CTX *ctx, const unsigned char *key_id_in, 
                                 unsigned char *key_out) {
    int ret = OQS_SUCCESS;
    
    QKD_DEBUG("Getting QKD key during encapsulation as responder");
    ON_ERR_SET_GOTO(!ctx || !key_id_in || !key_out, ret, OQS_ERROR, err);
    ON_ERR_SET_GOTO(ctx->is_initiator, ret, OQS_ERROR, err);

#ifdef ETSI_004_API
    // First establish session with received key ID
    memcpy(ctx->key_id, key_id_in, QKD_KSID_SIZE);
    if (!qkd_open_connect(ctx)) {
        QKD_DEBUG("Failed to establish QKD session");
        ret = OQS_ERROR;
        goto err;
    }
    // Then get the actual key
    if (!qkd_get_key(ctx)) {
        QKD_DEBUG("Failed to get QKD key");
        ret = OQS_ERROR;
        goto err;
    }

    // Extract key from EVP_PKEY
    if (ctx->key) {
        size_t keylen = 0;
        unsigned char *raw_key = NULL;

        if (EVP_PKEY_get_raw_private_key(ctx->key, NULL, &keylen) > 0) {
            if (keylen != QKD_KEY_SIZE) {
                QKD_DEBUG("Invalid QKD key length: %zu", keylen);
                ret = OQS_ERROR;
                goto err;
            }
            raw_key = OPENSSL_malloc(keylen);
            if (raw_key) {
                if (EVP_PKEY_get_raw_private_key(ctx->key, raw_key, &keylen) > 0) {
                    // Verify key is not all zeros
                    int is_zero = 1;
                    for (size_t i = 0; i < keylen; i++) {
                        if (raw_key[i] != 0) {
                            is_zero = 0;
                            break;
                        }
                    }
                    if (!is_zero) {
                        memcpy(key_out, raw_key, QKD_KEY_SIZE);
                    } else {
                        QKD_DEBUG("Error: Retrieved zero QKD key");
                        ret = OQS_ERROR;
                    }
                } else {
                    QKD_DEBUG("Failed to extract raw key material");
                    ret = OQS_ERROR;
                }
                OPENSSL_clear_free(raw_key, keylen);
            } else {
                QKD_DEBUG("Failed to allocate memory for raw key");
                ret = OQS_ERROR;
            }
        } else {
            QKD_DEBUG("Failed to get key length");
            ret = OQS_ERROR;
        }
    } else {
        QKD_DEBUG("No QKD key available");
        ret = OQS_ERROR;
    }

#elif defined(ETSI_014_API)
    memcpy(ctx->key_id, key_id_in, QKD_KSID_SIZE);
    if (!qkd_get_key_with_ids(ctx)) {
        QKD_DEBUG("Failed to get QKD key");
        ret = OQS_ERROR;
        goto err;
    }

    // Extract and validate key from EVP_PKEY
    if (ctx->key) {
        size_t keylen = 0;
        unsigned char *raw_key = NULL;

        if (EVP_PKEY_get_raw_private_key(ctx->key, NULL, &keylen) > 0) {
            if (keylen != QKD_KEY_SIZE) {
                QKD_DEBUG("Invalid QKD key length: %zu", keylen);
                ret = OQS_ERROR;
                goto err;
            }
            raw_key = OPENSSL_malloc(keylen);
            if (raw_key) {
                if (EVP_PKEY_get_raw_private_key(ctx->key, raw_key, &keylen) > 0) {
                    // Verify key is not all zeros
                    int is_zero = 1;
                    for (size_t i = 0; i < keylen; i++) {
                        if (raw_key[i] != 0) {
                            is_zero = 0;
                            break;
                        }
                    }
                    if (!is_zero) {
                        memcpy(key_out, raw_key, QKD_KEY_SIZE);
                        #if !defined(NDEBUG) && defined(DEBUG_QKD)
                        QKD_DEBUG("Retrieved QKD key material:");
                        for (size_t i = 0; i < keylen; i++) {
                            fprintf(stderr, "%02x", raw_key[i]);
                        }
                        fprintf(stderr, "\n");
                        #endif
                    } else {
                        QKD_DEBUG("Error: Retrieved zero QKD key");
                        ret = OQS_ERROR;
                    }
                } else {
                    QKD_DEBUG("Failed to extract raw key material");
                    ret = OQS_ERROR;
                }
                OPENSSL_clear_free(raw_key, keylen);
            } else {
                QKD_DEBUG("Failed to allocate memory for raw key");
                ret = OQS_ERROR;
            }
        } else {
            QKD_DEBUG("Failed to get key length");
            ret = OQS_ERROR;
        }
    } else {
        QKD_DEBUG("No QKD key available");
        ret = OQS_ERROR;
    }
#endif

    return ret;
err:
    return ret;
}

/* For key retrieval during decapsulation (Alice) */
static int oqs_qkd_get_decaps_key(OQSX_KEY *oqsx_key, unsigned char *key_out, int idx_qkd) {
    int ret = OQS_SUCCESS;
    QKD_CTX *ctx = oqsx_key->qkd_ctx;
    
    QKD_DEBUG("Getting QKD key during decapsulation as initiator");
    ON_ERR_SET_GOTO(!ctx || !key_out, ret, OQS_ERROR, err);
    ON_ERR_SET_GOTO(!ctx->is_initiator, ret, OQS_ERROR, err);

#ifdef ETSI_004_API
    // Get key using already established session
    if (!qkd_get_key(ctx)) {
        QKD_DEBUG("Failed to get QKD key");
        ret = OQS_ERROR;
        goto err;
    }

    // Extract and validate key from EVP_PKEY
    if (ctx->key) {
        size_t keylen = 0;
        unsigned char *raw_key = NULL;

        if (EVP_PKEY_get_raw_private_key(ctx->key, NULL, &keylen) > 0) {
            if (keylen != QKD_KEY_SIZE) {
                QKD_DEBUG("Invalid QKD key length: %zu", keylen);
                ret = OQS_ERROR;
                goto err;
            }
            raw_key = OPENSSL_malloc(keylen);
            if (raw_key) {
                if (EVP_PKEY_get_raw_private_key(ctx->key, raw_key, &keylen) > 0) {
                    // Verify key is not all zeros
                    int is_zero = 1;
                    for (size_t i = 0; i < keylen; i++) {
                        if (raw_key[i] != 0) {
                            is_zero = 0;
                            break;
                        }
                    }
                    if (!is_zero) {
                        memcpy(key_out, raw_key, QKD_KEY_SIZE);
                        #if !defined(NDEBUG) && defined(DEBUG_QKD)
                        QKD_DEBUG("Retrieved QKD key material in ETSI004 mode:");
                        for (size_t i = 0; i < keylen; i++) {
                            fprintf(stderr, "%02x", raw_key[i]);
                        }
                        fprintf(stderr, "\n");
                        #endif
                    } else {
                        QKD_DEBUG("Error: Retrieved zero QKD key");
                        ret = OQS_ERROR;
                    }
                } else {
                    QKD_DEBUG("Failed to extract raw key material");
                    ret = OQS_ERROR;
                }
                OPENSSL_clear_free(raw_key, keylen);
            } else {
                QKD_DEBUG("Failed to allocate memory for raw key");
                ret = OQS_ERROR;
            }
        } else {
            QKD_DEBUG("Failed to get key length");
            ret = OQS_ERROR;
        }
    } else {
        QKD_DEBUG("No QKD key available");
        ret = OQS_ERROR;
    }

#elif defined(ETSI_014_API)
    // Validate private key component exists
    ON_ERR_SET_GOTO(!oqsx_key->comp_privkey, ret, OQS_ERROR, err);
    ON_ERR_SET_GOTO(!oqsx_key->comp_privkey[idx_qkd], ret, OQS_ERROR, err);

    // Verify the stored key is not all zeros
    unsigned char *stored_key = oqsx_key->comp_privkey[idx_qkd];
    int is_zero = 1;
    for (size_t i = 0; i < QKD_KEY_SIZE; i++) {
        if (stored_key[i] != 0) {
            is_zero = 0;
            break;
        }
    }
    if (is_zero) {
        QKD_DEBUG("Error: Stored QKD key is zero");
        ret = OQS_ERROR;
        goto err;
    }

    // Copy the stored key from private key component
    memcpy(key_out, oqsx_key->comp_privkey[idx_qkd], QKD_KEY_SIZE);

    #if !defined(NDEBUG) && defined(DEBUG_QKD)
    QKD_DEBUG("DECAPS: Using stored QKD key from private key component (%d bytes): ", QKD_KEY_SIZE);
    for (size_t i = 0; i < QKD_KEY_SIZE; i++) {
        fprintf(stderr, "%02x", key_out[i]);
    }
    fprintf(stderr, "\n");
    #endif
#endif

    return ret;
err:
    if (key_out) {
        OPENSSL_secure_clear_free(key_out, QKD_KEY_SIZE);
    }
    return ret;
}

static int oqs_qkd_kem_encaps_keyslot(void *vpkemctx, unsigned char *ct,
                                      size_t *ctlen, unsigned char *secret,
                                      size_t *secretlen, int keyslot) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem;

#if !defined(NDEBUG) && defined(DEBUG_QKD)
    QKD_DEBUG("KEM encaps keyslot: %d", keyslot);
    if (oqsx_key && oqsx_key->comp_pubkey && oqsx_key->comp_pubkey[keyslot]) {
        printf("Public key for keyslot %d: ", keyslot);
        // For PQ key print length from KEM context
        if (keyslot == 0) { // PQ keyslot
            size_t pubkey_len = oqsx_key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
            printf("(%zu bytes): ", pubkey_len);
            for (size_t i = 0; i < pubkey_len; i++) {
                printf("%02x", ((unsigned char*)oqsx_key->comp_pubkey[keyslot])[i]);
            }
        } else { // QKD keyslot
            printf("(%d bytes): ", QKD_KSID_SIZE);
            for (size_t i = 0; i < QKD_KSID_SIZE; i++) {
                printf("%02x", ((unsigned char*)oqsx_key->comp_pubkey[keyslot])[i]);
            }
        }
        printf("\n");
    }
#endif

    // Validate KEM context
    ON_ERR_SET_GOTO(oqsx_key == NULL, ret, -1, err);

    // Set required lengths
    ON_ERR_SET_GOTO(ctlen == NULL, ret, -2, err);
    ON_ERR_SET_GOTO(secretlen == NULL, ret, -3, err);
    *ctlen = QKD_KSID_SIZE;
    *secretlen = QKD_KEY_SIZE;

    // If buffers are NULL, return lengths
    if (ct == NULL || secret == NULL) {
        OQS_KEM_PRINTF3("QKD KEM returning lengths %zu and %zu", *ctlen,
                        *secretlen);
        return 1;
    }

    // Validate public key components
    ON_ERR_SET_GOTO(oqsx_key->comp_pubkey == NULL, ret, -4, err);
    ON_ERR_SET_GOTO(oqsx_key->comp_pubkey[keyslot] == NULL, ret, -5, err);

    {
    #if !defined(NDEBUG) && defined(DEBUG_QKD)
        unsigned char *pubkey = (unsigned char *)oqsx_key->comp_pubkey[keyslot];
        fprintf(stderr, "comp_pubkey[%d] (QKD index): ", keyslot);
        for (size_t i = 0; i < QKD_KSID_SIZE; i++) {
            fprintf(stderr, "%02x", pubkey[i]);
        }
        fprintf(stderr, "\n");
    #endif
    }

    // Now Bob's role: Use received key ID to get key
    QKD_DEBUG("BEFORE GETTING QKD KEY");

    // print 
    if (!oqsx_key->qkd_ctx->is_initiator) {
        QKD_DEBUG("GETTING QKD KEY");
        ret = oqs_qkd_get_encaps_key(oqsx_key->qkd_ctx, 
                                    oqsx_key->comp_pubkey[keyslot],
                                    secret);
    }

    return ret;
err:
    // TODO_QKD: free resources if needed
    return ret;
}

static int oqs_qkd_kem_decaps_keyslot(void *vpkemctx, unsigned char *secret,
                                      size_t *secretlen,
                                      const unsigned char *ct, size_t ctlen,
                                      int keyslot) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem;

    if (secret == NULL) {
        QKD_DEBUG("OQS QKD KEM provider called: decaps_keyslot");
        return 1;
    }

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

    // because Bob has already called OPEN_CONNECT and retrieved his key
    // Now Alice's role: Get key using established session
    if (oqsx_key->qkd_ctx->is_initiator) {
        ret = oqs_qkd_get_decaps_key(oqsx_key, secret, keyslot);
    }

    QKD_DEBUG("QKD KEM decapsulation succeeded");
    return ret;

err:
    // TODO_QKD: free resources if needed
    return ret;
}

/// QKD-KEM hybrid functions
int oqs_qkd_kem_encaps(void *vpkemctx, unsigned char *ct, size_t *ctlen,
                       unsigned char *secret, size_t *secretlen) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem; // TODO_QKD: this used to be a const
    size_t secretLenQKD = QKD_KEY_SIZE;
    size_t ctLenQKD = QKD_KSID_SIZE;
    size_t secretLenPQ = 0, ctLenPQ = 0;
    unsigned char *ctQKD, *ctPQ, *secretQKD, *secretPQ;

    QKD_DEBUG("QKD KEM encaps starting");

    // Retrieve keyslot indices
    int idx_pq = -1, idx_qkd = -1;
    oqsx_comp_set_idx(oqsx_key, NULL, &idx_pq, &idx_qkd);

    if (idx_pq && idx_qkd) {
        QKD_DEBUG(
            "Error: Indices for classic, PQ, and QKD must be distinct.\n");
        goto err;
    }

    ON_ERR_SET_GOTO(idx_pq == -1 || idx_qkd == -1, ret, OQS_ERROR, err);

    //ret = oqs_init_qkd_context(oqsx_key, true); // Initialize as initiator
    //ON_ERR_SET_GOTO(ret < 0, ret, OQS_ERROR, err);

    // Check for NULL public key components directly in qkdkemctx
    ON_ERR_SET_GOTO(oqsx_key->comp_pubkey == NULL, ret, OQS_ERROR, err);

    if (oqsx_key && oqsx_key->comp_pubkey && oqsx_key->comp_pubkey[idx_pq]) {
        size_t pq_pubkey_len = oqsx_key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        unsigned char *pq_pub = (unsigned char *)oqsx_key->comp_pubkey[idx_pq];
        QKD_DEBUG("__________PQC public key (keyslot %d, %zu bytes):", idx_pq, pq_pubkey_len);
        //for (size_t i = 0; i < pq_pubkey_len; i++) {
        //    printf("%02x", pq_pub[i]);
        //}
        printf("\n");
    }

    if (oqsx_key && oqsx_key->comp_pubkey && oqsx_key->comp_pubkey[idx_qkd]) {
        size_t qkd_pubkey_len = QKD_KSID_SIZE;
        unsigned char *qkd_pub = (unsigned char *)oqsx_key->comp_pubkey[idx_qkd];
        QKD_DEBUG("__________QKD public key (keyslot %d, %zu bytes):", idx_qkd, qkd_pubkey_len);
        #if !defined(NDEBUG) && defined(DEBUG_QKD)
        for (size_t i = 0; i < qkd_pubkey_len; i++) {
            printf("%02x", qkd_pub[i]);
        }
        printf("\n");
        #endif
    }

    QKD_DEBUG("ENCAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);
    QKD_DEBUG("DECAPS: BEFORE GETTING QKD KEY");
        if (oqsx_key && oqsx_key->qkd_ctx) {
        QKD_DEBUG("ENCAPS QKD URIs:");
        QKD_DEBUG("Source URI: %s", 
                  oqsx_key->qkd_ctx->source_uri ? oqsx_key->qkd_ctx->source_uri : "NULL");
        QKD_DEBUG("Destination URI: %s", 
                  oqsx_key->qkd_ctx->dest_uri ? oqsx_key->qkd_ctx->dest_uri : "NULL");
    } else {
        QKD_DEBUG("QKD context or URIs not available");
    }

    // Initialize QKD context as responder
    ret = oqs_init_qkd_context(oqsx_key, false);
    // print initiator role
    QKD_DEBUG("ENCAPS: Initiator role: %d", oqsx_key->qkd_ctx->is_initiator);
    ON_ERR_SET_GOTO(ret != OQS_SUCCESS, ret, OQS_ERROR, err);

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
    QKD_DEBUG("ENCAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);
    // Encapsulate QKD key
    ret = oqs_qkd_kem_encaps_keyslot(vpkemctx, ctQKD, &ctLenQKD, secretQKD,
                                     &secretLenQKD, idx_qkd);
    // print ret value
    ON_ERR_SET_GOTO(ret < 0, ret, OQS_ERROR, err);
    // Encapsulate PQ key
    ret = oqs_qs_kem_encaps_keyslot(vpkemctx, ctPQ, &ctLenPQ, secretPQ,
                                    &secretLenPQ, idx_pq);

#if !defined(NDEBUG) && defined(DEBUG_QKD)
    QKD_DEBUG("ENCAPS: ret value: %d", ret);
    QKD_DEBUG("ENCAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);

    printf("ENCAPS: PQ Shared Secret (%zu bytes): ", secretLenPQ);
    for (size_t i = 0; i < secretLenPQ; i++) {
        printf("%02x", secretPQ[i]);
    }
    printf("\nENCAPS: QKD Shared Secret (%zu bytes): ", secretLenQKD);
    for (size_t i = 0; i < secretLenQKD; i++) {
        printf("%02x", secretQKD[i]);
    }
    printf("\nENCAPS: Full Shared Secret (%zu bytes): ", *secretlen);
    for (size_t i = 0; i < *secretlen; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");
#endif
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);    QKD_DEBUG("After first qs_kem encaps_keyslot call");

    QKD_DEBUG("QKD KEM encaps completed successfully");

err:
    QKD_DEBUG("QKD KEM encaps finishing with ret=%d", ret);
    return ret;
}

/* QKD: Have into account that if we don't have the classical part, we cannot
detect tampering and the return will be 1 from the PQ part */
int oqs_qkd_kem_decaps(void *vpkemctx, unsigned char *secret, size_t *secretlen,
                       const unsigned char *ct, size_t ctlen) {
    int ret = OQS_SUCCESS;
    PROV_OQSKEM_CTX *qkdkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    OQSX_KEY *oqsx_key = qkdkemctx->kem; // TODO_QKD: this used to be a const
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

    ret = oqs_init_qkd_context(oqsx_key, true); // Initialize as initiator
    ON_ERR_SET_GOTO(ret < 0, ret, OQS_ERROR, err);
    QKD_DEBUG("DECAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);

    // Get PQ lengths
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, NULL, &secretLenPQ, NULL, 0,
                                    idx_pq);
    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    if (oqsx_key && oqsx_key->comp_pubkey && oqsx_key->comp_pubkey[idx_pq]) {
        size_t pq_pubkey_len = oqsx_key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
        unsigned char *pq_pub = (unsigned char *)oqsx_key->comp_pubkey[idx_pq];
        QKD_DEBUG("__________PQC public key (keyslot %d, %zu bytes):", idx_pq, pq_pubkey_len);
        //for (size_t i = 0; i < pq_pubkey_len; i++) {
        //    printf("%02x", pq_pub[i]);
        //}
        printf("\n");
    }

    QKD_DEBUG("After firs decaps_keyslot call");

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
#if !defined(NDEBUG) && defined(DEBUG_QKD)
        printf("\nDECAPS QKD Ciphertext (%zu bytes): ", ctLenQKD);
        for (size_t i = 0; i < ctLenQKD; i++) {
            printf("%02x", ctQKD[i]);
        }
        printf("\n");
#endif
    } else {
        // TODO_QKD: implement the triple hybrid case
        // raise error
        QKD_DEBUG("Error: Triple hybrid case not implemented yet.\n");
        goto err;
    }

#if !defined(NDEBUG) && defined(DEBUG_QKD)
    if (oqsx_key->comp_pubkey && oqsx_key->comp_pubkey[idx_qkd]) {
        printf("DECAPS: QKD Public Key (key_id) (%d bytes): ", QKD_KSID_SIZE);
        for (size_t i = 0; i < QKD_KSID_SIZE; i++) {
            printf("%02x", ((unsigned char*)oqsx_key->comp_pubkey[idx_qkd])[i]);
        }
        printf("\n");
    } else {
        printf("DECAPS: QKD Public Key is NULL\n");
    }
#endif
    QKD_DEBUG("DECAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);
    QKD_DEBUG("DECAPS: Initiator role: %d", oqsx_key->qkd_ctx->is_initiator);
    // Perform QKD decapsulation
    //ret = oqs_qkd_kem_decaps_keyslot(vpkemctx, secretQKD, &secretLenQKD, ctQKD,
    //                                 ctLenQKD, idx_qkd);
    // TODO_QKD: check if we should use the ciphertext from the QKD part. Test with TLS
    ret = oqs_qkd_kem_decaps_keyslot(vpkemctx, secretQKD, &secretLenQKD,
                                     oqsx_key->comp_pubkey[idx_qkd],
                                     QKD_KSID_SIZE, idx_qkd);
#if !defined(NDEBUG) && defined(DEBUG_QKD)
    QKD_DEBUG("DECAPS: ret value: %d", ret);
    QKD_DEBUG("DECAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);


    printf("\nDECAPS: QKD Shared Secret (%zu bytes): ", secretLenQKD);
    for (size_t i = 0; i < secretLenQKD; i++) {
        printf("%02x", secretQKD[i]);
    }

    printf("\n");
#endif

    ON_ERR_SET_GOTO(ret < 0, ret, OQS_ERROR, err);

    QKD_DEBUG("After first qkd_kem decaps_keyslot call");

    // Perform PQ decapsulation
    ret = oqs_qs_kem_decaps_keyslot(vpkemctx, secretPQ, &secretLenPQ, ctPQ,
                                    ctLenPQ, idx_pq);
#if !defined(NDEBUG) && defined(DEBUG_QKD)
    QKD_DEBUG("DECAPS: ret value: %d", ret);
    QKD_DEBUG("DECAPS: pq index: %d, qkd index: %d", idx_pq, idx_qkd);

    printf("DECAPS: PQ Shared Secret (%zu bytes): ", secretLenPQ);
    for (size_t i = 0; i < secretLenPQ; i++) {
        printf("%02x", secretPQ[i]);
    }
    printf("\nDECAPS: QKD Shared Secret (%zu bytes): ", secretLenQKD);
    for (size_t i = 0; i < secretLenQKD; i++) {
        printf("%02x", secretQKD[i]);
    }
    printf("\nDECAPS: Full Shared Secret (%zu bytes): ", *secretlen);
    for (size_t i = 0; i < *secretlen; i++) {
        printf("%02x", secret[i]);
    }
    printf("\n");
#endif

    ON_ERR_SET_GOTO(ret <= 0, ret, OQS_ERROR, err);

    QKD_DEBUG("After first qs_kem decaps_keyslot call");

    QKD_DEBUG("QKD KEM decaps completed successfully");
err:
    return ret;
}