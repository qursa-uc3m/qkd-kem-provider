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
#include <qkd-etsi-api/api.h>
#include <stdlib.h>
#include <string.h>

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