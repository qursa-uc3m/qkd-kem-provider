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

    if (!ctx->source_uri)
        ctx->source_uri = "qkd://localhost:1234";
    if (!ctx->dest_uri)
        ctx->dest_uri = "qkd://localhost:5678";

    uint32_t status;
    // unsigned char key_stream_id[QKD_KSID_SIZE] = {0};

    uint32_t result = OPEN_CONNECT(ctx->source_uri, ctx->dest_uri, &ctx->qos,
                                   ctx->key_id, &status);

    QKD_DEBUG("%s", ctx->is_initiator ? "Initiator case" : "Responder case");

    QKD_DEBUG("OPEN_CONNECT returned result=%u status=%u", result, status);

    if (result == QKD_STATUS_SUCCESS ||
        result == QKD_STATUS_PEER_DISCONNECTED) {
        ctx->is_connected = true;
        QKD_DEBUG("Connection established successfully");
        return true;
    }

    QKD_DEBUG("Connection failed");
    return false;
}

bool qkd_get_key(QKD_CTX *ctx) {

    if (!ctx) {
        // TODO_QKD: should we check if the context is connected?
        QKD_DEBUG("Invalid context or not connected");
        return false;
    }

    uint32_t status;
    uint32_t index = 0;
    unsigned char key_buffer[QKD_KEY_SIZE];

    QKD_DEBUG("Getting key for stream ID %s", ctx->key_id);
    uint32_t result =
        GET_KEY(ctx->key_id, &index, key_buffer, &ctx->metadata, &status);

    if (result == 0 && (status == QKD_STATUS_SUCCESS ||
                        status == QKD_STATUS_PEER_DISCONNECTED)) {
        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                key_buffer, QKD_KEY_SIZE);
        if (!ctx->key) {
            QKD_DEBUG("EVP_PKEY conversion failed");
            return false;
        }
        QKD_DEBUG("Key successfully generated");
        return true;
    }

    QKD_DEBUG("Key generation failed: result=%u status=%u", result, status);
    return false;
}

/* Close connection using ETSI API */
bool qkd_close(QKD_CTX *ctx) {
    if (!ctx || !ctx->is_connected) {
        QKD_DEBUG("Invalid context or not connected");
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
        QKD_DEBUG("Connection closed successfully");
        return true;
    }

    QKD_DEBUG("Failed to close connection");
    return false;
}
#endif /* ETSI_004_API */

#ifdef ETSI_014_API

static unsigned char *base64_decode(const char *in, size_t *outlen) {
    // For simplicity, this uses OpenSSL's built-in Base64 decode routines.
    // You need to ensure that `in` is a null-terminated base64 string.
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void*)in, -1);
    bmem = BIO_push(b64, bmem);
    BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);

    // Estimate output length
    size_t inlen = strlen(in);
    unsigned char *out = malloc(inlen); // base64 expands data by ~33%, so this is safe
    *outlen = BIO_read(bmem, out, inlen);
    BIO_free_all(bmem);

    if (*outlen <= 0) {
        free(out);
        return NULL;
    }
    return out;
}

bool qkd_get_status(QKD_CTX *ctx) {
    if (!ctx || !ctx->dest_uri) {
        QKD_DEBUG("Invalid ctx or missing dest_uri");
        return false;
    }
    QKD_DEBUG("Requesting status from KME");

    qkd_status_t status_resp;
    memset(&status_resp, 0, sizeof(status_resp));

    uint32_t ret = GET_STATUS(ctx->source_uri, ctx->dest_uri, &status_resp);
    if (ret == QKD_STATUS_OK) {
        QKD_DEBUG("Got status from ETSI QKD 014 KME");
        // You may store or use status_resp fields if needed:
        // e.g., status_resp.key_size, status_resp.stored_key_count, etc.
        // If you allocate memory in GET_STATUS internally, remember to free it here.
        return true;
    } else {
        QKD_DEBUG("Failed to get status: ret=%u", ret);
        return false;
    }
}

bool qkd_get_key(QKD_CTX *ctx) {
    if (!ctx || !ctx->dest_uri) {
        QKD_DEBUG("Invalid ctx");
        return false;
    }

    qkd_key_request_t req;
    memset(&req, 0, sizeof(req));
    req.number = 1; // request one key
    // If you know the desired key size, set req.size here. Otherwise rely on default.

    qkd_key_container_t container;
    memset(&container, 0, sizeof(container));
    QKD_DEBUG("Requesting key from KME");
    uint32_t ret = GET_KEY(ctx->source_uri, ctx->dest_uri, &req, &container);
    if (ret == QKD_STATUS_OK && container.key_count > 0) {
        QKD_DEBUG("Got %d keys from KME", container.key_count);

        // For simplicity, take the first key
        qkd_key_t *first_key = &container.keys[0];
        if (!first_key->key) {
            QKD_DEBUG("No key data returned");
            return false;
        }

        size_t outlen;
        unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
        if (!decoded_key) {
            QKD_DEBUG("Base64 decode failed");
            return false;
        }

        // Create an EVP_PKEY from the decoded raw key bytes.
        // Adjust the EVP_PKEY type and length as appropriate for your use case.
        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, decoded_key, outlen);
        free(decoded_key);

        if (!ctx->key) {
            QKD_DEBUG("EVP_PKEY_new_raw_private_key failed");
            return false;
        }

        QKD_DEBUG("Key successfully retrieved and stored");
        return true;
    } else {
        QKD_DEBUG("GET_KEY call failed: ret=%u or no keys returned", ret);
        return false;
    }
}

bool qkd_get_key_with_ids(QKD_CTX *ctx) {
    if (!ctx || !ctx->dest_uri) {
        QKD_DEBUG("Invalid ctx");
        return false;
    }
    QKD_DEBUG("Requesting key from KME using key IDs");
    // For example, assume ctx->key_id stores a single key_id as a null-terminated string.
    // If you need multiple key_ids, adapt this accordingly.
    qkd_key_ids_t key_ids;
    memset(&key_ids, 0, sizeof(key_ids));

    key_ids.key_ID_count = 1;
    key_ids.key_IDs = malloc(sizeof(qkd_key_id_t));
    if (!key_ids.key_IDs) {
        QKD_DEBUG("Memory allocation failed");
        return false;
    }
    memset(key_ids.key_IDs, 0, sizeof(qkd_key_id_t));

    // Assume ctx->key_id is a UUID string
    key_ids.key_IDs[0].key_ID = strdup((char *)ctx->key_id);
    if (!key_ids.key_IDs[0].key_ID) {
        QKD_DEBUG("Memory allocation for key_ID failed");
        free(key_ids.key_IDs);
        return false;
    }

    qkd_key_container_t container;
    memset(&container, 0, sizeof(container));

    uint32_t ret = GET_KEY_WITH_IDS(ctx->source_uri, ctx->dest_uri, &key_ids, &container);
    free(key_ids.key_IDs[0].key_ID);
    free(key_ids.key_IDs);

    if (ret == QKD_STATUS_OK && container.key_count > 0) {
        QKD_DEBUG("Got %d keys from KME using key IDs", container.key_count);

        qkd_key_t *first_key = &container.keys[0];
        if (!first_key->key) {
            QKD_DEBUG("No key data returned");
            return false;
        }

        size_t outlen;
        unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
        if (!decoded_key) {
            QKD_DEBUG("Base64 decode failed");
            return false;
        }

        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL, decoded_key, outlen);
        free(decoded_key);

        if (!ctx->key) {
            QKD_DEBUG("EVP_PKEY_new_raw_private_key failed");
            return false;
        }

        QKD_DEBUG("Key successfully retrieved by key IDs and stored");
        return true;
    } else {
        QKD_DEBUG("GET_KEY_WITH_IDS call failed: ret=%u or no keys returned", ret);
        return false;
    }
}

#endif /* ETSI_014_API */