/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_etsi_api_wrapper.c
 * Wrapper for QKD ETSI API to maintain compatibility with existing QKD_CTX
 * interface
 */

#include "oqs_qkd_etsi_api_wrapper.h"
#include "oqs_qkd_kem.h"
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <stdlib.h>
#include <string.h>

#include <qkd-etsi-api/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api/etsi014/api.h>
#endif

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

#ifdef ETSI_004_API
/* Initialize QKD context and map to ETSI API */
bool qkd_open(QKD_CTX *ctx) {
    if (!ctx)
        return false;
    /*
    if (!ctx->source_uri)
        ctx->source_uri = "qkd://localhost:1234";
    if (!ctx->dest_uri)
        ctx->dest_uri = "qkd://localhost:5678";
    */
    uint32_t status;
    // unsigned char key_stream_id[QKD_KSID_SIZE] = {0};

    uint32_t result = OPEN_CONNECT(ctx->source_uri, ctx->dest_uri, &ctx->qos,
                                   ctx->key_id, &status);

    QKD_DEBUG("%s", ctx->is_initiator ? "Initiator case" : "Responder case");

    QKD_DEBUG("ETSI004: OPEN_CONNECT returned result=%u status=%u", result, status);

    if (result == QKD_STATUS_SUCCESS ||
        result == QKD_STATUS_PEER_DISCONNECTED) {
        ctx->is_connected = true;
        QKD_DEBUG("ETSI004: Connection established successfully");
        return true;
    }

    QKD_DEBUG("ETSI004: Connection failed");
    return false;
}


/* Close connection using ETSI API */
bool qkd_close(QKD_CTX *ctx) {
    if (!ctx || !ctx->is_connected) {
        QKD_DEBUG("ETSI004: Invalid context or not connected");
        return false;
    }

    uint32_t status;
    unsigned char key_stream_id[QKD_KSID_SIZE] = {0};
    memcpy(key_stream_id, ctx->key_id, QKD_KSID_SIZE);

    uint32_t result = CLOSE(key_stream_id, &status);

    if (result == 0 && (status == QKD_STATUS_SUCCESS ||
                        status == QKD_STATUS_PEER_DISCONNECTED)) {
        ctx->is_connected = false;
        if (ctx->key) {
            EVP_PKEY_free(ctx->key);
            ctx->key = NULL;
        }
        QKD_DEBUG("ETSI004: Connection closed successfully");
        return true;
    }

    QKD_DEBUG("ETSI004: Failed to close connection");
    return false;
}
#endif /* ETSI_004_API */

#ifdef ETSI_014_API

static unsigned char *base64_decode(const char *in, size_t *outlen) {

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void*)in, -1);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    // Estimate output length
    size_t inlen = strlen(in);
    unsigned char *out = malloc(inlen);
    *outlen = BIO_read(bmem, out, inlen);
    BIO_free_all(bmem);

    if (*outlen <= 0) {
        free(out);
        return NULL;
    }
    return out;
}

bool qkd_get_status(QKD_CTX *ctx) {

    QKD_DEBUG("ETSI014: Requesting status from KME");

    if (!ctx) {
        QKD_DEBUG("ETSI014: Invalid ctx");
        return false;
    }

    if (!ctx->source_uri || !ctx->dest_uri) {
        QKD_DEBUG("ETSI014: NULL URIs before GET_KEY call");
        return false;
    }

    if (!ctx->status.source_KME_ID) {
        QKD_DEBUG("ETSI014: No source KME ID set");
    }

    QKD_DEBUG("ETSI014: Requesting status from KME");
    
    //qkd_status_t status_resp;
    //memset(&status_resp, 0, sizeof(status_resp));
    QKD_DEBUG("ETSI014: Requesting status from KME with source=%s, dest=%s", 
              ctx->source_uri, ctx->dest_uri);
    uint32_t ret = GET_STATUS(ctx->source_uri, ctx->dest_uri, &ctx->status);

    QKD_DEBUG("ETSI014: GET_STATUS returned %u", ret);
    if (ret == QKD_STATUS_OK) {
        QKD_DEBUG("ETSI014: Got status from ETSI QKD 014 KME");
        return true;
    } else {
        QKD_DEBUG("ETSI014: Failed to get status: ret=%u", ret);
        return false;
    }
   return true;
}

bool qkd_get_key_with_ids(QKD_CTX *ctx) {
    if (!ctx || !ctx->dest_uri) {
        QKD_DEBUG("ETSI 014: Invalid ctx");
        return false;
    }
    QKD_DEBUG("ETSI 014: Requesting key from KME using key IDs");
    // We assume ctx->key_id stores a single key_id as a null-terminated string.
    qkd_key_ids_t key_ids;
    memset(&key_ids, 0, sizeof(key_ids));

    key_ids.key_ID_count = 1;
    key_ids.key_IDs = malloc(sizeof(qkd_key_id_t));
    if (!key_ids.key_IDs) {
        QKD_DEBUG("ETSI014: Memory allocation failed");
        return false;
    }
    memset(key_ids.key_IDs, 0, sizeof(qkd_key_id_t));

    // Assume ctx->key_id is a UUID string
    key_ids.key_IDs[0].key_ID = strdup((char *)ctx->key_id);
    if (!key_ids.key_IDs[0].key_ID) {
        QKD_DEBUG("ETSI014: Memory allocation for key_ID failed");
        free(key_ids.key_IDs);
        return false;
    }

    qkd_key_container_t container;
    memset(&container, 0, sizeof(container));

    uint32_t ret = GET_KEY_WITH_IDS(ctx->source_uri, ctx->dest_uri, &key_ids, &container);
    free(key_ids.key_IDs[0].key_ID);
    free(key_ids.key_IDs);

    if (ret == QKD_STATUS_OK && container.key_count > 0) {
        QKD_DEBUG("ETSI014: Got %d keys from KME using key IDs", container.key_count);

        qkd_key_t *first_key = &container.keys[0];
        if (!first_key->key) {
            QKD_DEBUG("ETSI014: No key data returned");
            return false;
        }

        size_t outlen;
        unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
        if (!decoded_key) {
            QKD_DEBUG("ETSI014: Base64 decode failed");
            return false;
        }

        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, decoded_key, outlen);
        free(decoded_key);

        if (!ctx->key) {
            QKD_DEBUG("ETSI014: EVP_PKEY_new_raw_private_key failed");
            return false;
        }

        QKD_DEBUG("ETSI014: Key successfully retrieved by key IDs and stored");
        return true;
    } else {
        QKD_DEBUG("ETSI014: GET_KEY_WITH_IDS call failed: ret=%u or no keys returned", ret);
        return false;
    }
}

#endif /* ETSI_014_API */

bool qkd_get_key(QKD_CTX *ctx) {
    if (!ctx) {
        QKD_DEBUG("Invalid QKD context");
        return false;
    }

#ifdef ETSI_004_API
    uint32_t status;
    uint32_t index = 0;
    unsigned char key_buffer[QKD_KEY_SIZE];

    QKD_DEBUG("ETSI004: Getting key for stream ID");
    uint32_t result = GET_KEY(ctx->key_id, &index, key_buffer, &ctx->metadata, &status);

    if (result == 0 && (status == QKD_STATUS_SUCCESS || 
                       status == QKD_STATUS_PEER_DISCONNECTED)) {
        // Convert key to EVP format
        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                               key_buffer, QKD_KEY_SIZE);
        if (!ctx->key) {
            QKD_DEBUG("ETSI004: EVP_PKEY conversion failed");
            return false;
        }
        QKD_DEBUG("ETSI004: Key successfully generated");
        return true;
    }
    QKD_DEBUG("ETSI004: Key generation failed: result=%u status=%u", result, status);
    return false;

#elif defined(ETSI_014_API)
    if (!ctx->source_uri || !ctx->dest_uri) {
        QKD_DEBUG("ETSI014: NULL URIs before GET_KEY call");
        return false;
    }

    // Prepare request
    qkd_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.number = 1;
    req.size = QKD_KEY_SIZE;

    qkd_key_container_t container;
    memset(&container, 0, sizeof(container));
    
    QKD_DEBUG("ETSI014: Requesting key from KME with source=%s, dest=%s",
              ctx->source_uri, ctx->dest_uri);
    
    uint32_t ret = GET_KEY(ctx->source_uri, ctx->dest_uri, &req, &container);
    QKD_DEBUG("ETSI014: GET_KEY returned %u", ret);

    if (ret == QKD_STATUS_OK && container.key_count > 0) {
        qkd_key_t *first_key = &container.keys[0];
        if (!first_key->key) {
            QKD_DEBUG("ETSI014: No key data returned");
            return false;
        }

        // Store key ID if provided
        if (first_key->key_ID) {
            unsigned char tmp_id;
            for(int i = 0; i < QKD_KSID_SIZE; i++) {
                sscanf(first_key->key_ID + (i * 2), "%02hhx", &tmp_id);
                ctx->key_id[i] = tmp_id;
            }
        }

        // Decode and store key
        size_t outlen;
        unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
        if (!decoded_key) {
            QKD_DEBUG("ETSI014: Base64 decode failed");
            return false;
        }

        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, 
                                               decoded_key, outlen);
        free(decoded_key);

        if (!ctx->key) {
            QKD_DEBUG("ETSI014: EVP_PKEY_new_raw_private_key failed");
            return false;
        }

        QKD_DEBUG("ETSI014: Key successfully retrieved and stored");
        return true;
    }

    QKD_DEBUG("ETSI014: GET_KEY call failed: ret=%u or no keys returned", ret);
    return false;
#endif
}