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

#include <qkd-etsi-api-c-wrapper/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api-c-wrapper/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api-c-wrapper/etsi014/api.h>
#endif

#include <uuid/uuid.h>

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

    QKD_DEBUG("ETSI004: OPEN_CONNECT returned result=%u status=%u", result,
              status);

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

/* Returns 0 on success, non-zero on error */
static int encode_UUID(const char *uuid_str, unsigned char bin[16]) {
    /* uuid_parse returns 0 on success and -1 on error */
    if (uuid_parse(uuid_str, bin) == -1)
        return -1;
    return 0;
}

/* Decode the 16-byte binary UUID to a string.
 * uuid_str must be able to hold at least 37 bytes (36 characters + null).
 */
static void decode_UUID(const unsigned char bin[16], char uuid_str[37]) {
    uuid_unparse(bin, uuid_str);
}

static unsigned char *base64_decode(const char *in, size_t *outlen) {

    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new_mem_buf((void *)in, -1);
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

    DEBUG_QKD("[DEBUG TEST] qkd_get_status is executing!\n");

    if (!ctx || !ctx->source_uri || !ctx->sae_id) {
        QKD_DEBUG("ETSI014: Invalid ctx or missing KME/SAE info");
        return false;
    }

    QKD_DEBUG("ETSI014: Requesting status from KME with hostname=%s, SAE=%s",
              ctx->source_uri, ctx->sae_id);

    // Let API handle URL construction
    uint32_t ret = GET_STATUS(ctx->master_kme, ctx->slave_sae, &ctx->status);

    QKD_DEBUG("ETSI014: get_status returned %u", ret);
    if (ret == QKD_STATUS_OK) {
        QKD_DEBUG("ETSI014: Status received from KME");
        QKD_DEBUG("ETSI014: Source KME ID: %s", ctx->status.source_KME_ID
                                                    ? ctx->status.source_KME_ID
                                                    : "NULL");
        return true;
    }

    QKD_DEBUG("ETSI014: Failed to get status: ret=%u", ret);
    return false;
}

bool qkd_get_key_with_ids(QKD_CTX *ctx) {
    if (!ctx || !ctx->dest_uri) {
        QKD_DEBUG("ETSI 014: Invalid ctx");
        return false;
    }
    QKD_DEBUG("ETSI 014: Requesting key from KME using key IDs");
    QKD_DEBUG("ETSI 014: Initial state - Is initiator: %d", ctx->is_initiator);

    // We assume ctx->key_id stores a single key_id as a null-terminated string.
    qkd_key_ids_t key_ids = {0};
    key_ids.key_ID_count = 1;
    key_ids.key_IDs = malloc(sizeof(qkd_key_id_t));
    if (!key_ids.key_IDs) {
        QKD_DEBUG("ETSI014: Memory allocation failed");
        return false;
    }

#ifdef QKD_USE_QUKAYDEE
    QKD_DEBUG("ETSI014: Using QuKayDee Backend ... Tailoring key ID formats");
#endif

    // Convert binary UUID back to string format for API
    char uuid_str[37]; // 36 chars + null terminator
    decode_UUID(ctx->key_id, uuid_str);
    QKD_DEBUG("ETSI014: Using key ID: %s", uuid_str);
    key_ids.key_IDs[0].key_ID = strdup(uuid_str);
    if (!key_ids.key_IDs[0].key_ID) {
        QKD_DEBUG("ETSI014: Memory allocation for key_ID failed");
        free(key_ids.key_IDs);
        return false;
    }

    qkd_key_container_t container;
    memset(&container, 0, sizeof(container));

    // kme_hostname: Bob's KME (slave)
    // master_sae_id: Alice's SAE ID (master who originally got the key)
    QKD_DEBUG("ETSI014: Calling GET_KEY_WITH_IDS - KME: %s, Master SAE: %s, "
              "Key ID: %s",
              ctx->slave_kme, ctx->master_sae, key_ids.key_IDs[0].key_ID);

    uint32_t ret =
        GET_KEY_WITH_IDS(ctx->slave_kme, ctx->master_sae, &key_ids, &container);

    free(key_ids.key_IDs[0].key_ID);
    free(key_ids.key_IDs);

    // Check the result and key_count
    if (ret != QKD_STATUS_OK) {
        QKD_DEBUG("ETSI014: GET_KEY_WITH_IDS call failed, ret=%u", ret);
        return false;
    }
    if (container.key_count == 0) {
        QKD_DEBUG("ETSI014: GET_KEY_WITH_IDS returned zero keys");
        return false;
    }

    // We only grab the first key
    qkd_key_t *first_key = &container.keys[0];
    if (!first_key->key) {
        QKD_DEBUG("ETSI014: No key data returned in the first key");
        return false;
    }

    QKD_DEBUG("ETSI014: Base64-decoding returned key");

    // Base64 decode the key material
    size_t outlen = 0;
    unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
    if (!decoded_key) {
        QKD_DEBUG("ETSI014: Base64 decode failed");
        return false;
    }

    // Validate the decoded key length for X25519 (should be 32 bytes typically)
    if (outlen != 32) {
        QKD_DEBUG("ETSI014: Decoded key length [%zu] is invalid for X25519",
                  outlen);
        OPENSSL_cleanse(decoded_key, outlen);
        free(decoded_key);
        return false;
    }

    // Clean up previously stored key if present
    if (ctx->key) {
        QKD_DEBUG("ETSI014: Freeing previously stored EVP_PKEY");
        EVP_PKEY_free(ctx->key);
        ctx->key = NULL;
    }

    // Create the EVP_PKEY with the decoded key material
    EVP_PKEY *temp_pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                       decoded_key, outlen);
    if (!temp_pkey) {
        QKD_DEBUG("ETSI014: EVP_PKEY_new_raw_private_key failed");
        OPENSSL_cleanse(decoded_key, outlen);
        free(decoded_key);
        return false;
    }

    // Wipe the decoded buffer from memory once we've used it
    OPENSSL_cleanse(decoded_key, outlen);
    free(decoded_key);

    // Store the newly created key in the context
    ctx->key = temp_pkey;

    QKD_DEBUG("ETSI014: Key successfully retrieved by key IDs and stored");
    return true;
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
    uint32_t result =
        GET_KEY(ctx->key_id, &index, key_buffer, &ctx->metadata, &status);

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
    QKD_DEBUG("ETSI004: Key generation failed: result=%u status=%u", result,
              status);
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

    QKD_DEBUG("\nETSI014: Requesting key from KME with source=%s, dest=%s",
              ctx->source_uri, ctx->dest_uri);

    uint32_t ret = GET_KEY(ctx->master_kme, ctx->slave_sae, &req, &container);
    QKD_DEBUG("\nETSI014: GET_KEY returned %u", ret);

    char *alice_key_id = strdup(container.keys[0].key_ID);
    QKD_DEBUG("[SUCCESS]: ALICE got key with ID: %s\n", alice_key_id);
    free(alice_key_id);

    if (ret == QKD_STATUS_OK && container.key_count > 0) {
        qkd_key_t *first_key = &container.keys[0];
        if (!first_key->key) {
            QKD_DEBUG("ETSI014: No key data returned");
            return false;
        }

        // Store key ID if provided
        if (first_key->key_ID) {
            QKD_DEBUG("ETSI014: Received key ID: %s", first_key->key_ID);

            // Convert UUID string to binary format for storage
            if (encode_UUID(first_key->key_ID, ctx->key_id) != 0) {
                QKD_DEBUG("ETSI014: Failed to encode UUID");
                return false;
            }
            QKD_DEBUG("ETSI014: Successfully encoded UUID to binary");
        }

        // Decode base64 key
        size_t outlen;
        unsigned char *decoded_key = base64_decode(first_key->key, &outlen);
        if (!decoded_key) {
            QKD_DEBUG("ETSI014: Base64 decode failed");
            return false;
        }

        // Check for zero key
        int is_zero = 1;
        for (size_t i = 0; i < outlen; i++) {
            if (decoded_key[i] != 0) {
                is_zero = 0;
                break;
            }
        }

        // Print the decoded key in hex
        QKD_DEBUG("ETSI014: Decoded key (hex dump):");
    #if !defined(NDEBUG) && defined(DEBUG_QKD)
        for (size_t i = 0; i < outlen; i++) {
            fprintf(stderr, "%02X ", decoded_key[i]);
        }
        fprintf(stderr, "\n");
    #endif

        if (is_zero) {
            QKD_DEBUG("ETSI014: Decoded key is all zeros");
            OPENSSL_clear_free(decoded_key, outlen);
            return false;
        }

        // Free previous key if it exists
        if (ctx->key) {
            EVP_PKEY_free(ctx->key);
            ctx->key = NULL;
        }

        // Create new EVP_PKEY with the decoded key
        ctx->key = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                decoded_key, outlen);
        OPENSSL_clear_free(decoded_key, outlen);

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