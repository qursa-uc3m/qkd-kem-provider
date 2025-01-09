/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_ctx.c
 * QKD context initialization
 */
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

static int qkd_init_uris(QKD_CTX *ctx) {
    int ret = OQS_SUCCESS;
    
    if (!ctx) {
        QKD_DEBUG("Invalid context");
        return OQS_ERROR;
    }

    // Using hardcoded values for now
    // TODO_QKD: put in openssl.cnf file
    const char *env_source_uri = "qkd://localhost:1234";
    const char *env_dest_uri = "qkd://localhost:5678";

    // Initialize source URI if not set
    if (!ctx->source_uri) {
        if (!env_source_uri) {
            QKD_DEBUG("Error: QKD_SOURCE_URI not defined");
            return OQS_ERROR;
        }
        ctx->source_uri = OPENSSL_strdup(env_source_uri);
        if (!ctx->source_uri) {
            QKD_DEBUG("Error: Failed to allocate memory for source_uri");
            return OQS_ERROR;
        }
    }

    // Initialize destination URI if not set
    if (!ctx->dest_uri) {
        if (!env_dest_uri) {
            QKD_DEBUG("Error: QKD_DEST_URI not defined");
            // Clean up source_uri
            if (ctx->source_uri) {
                OPENSSL_free(ctx->source_uri);
                ctx->source_uri = NULL;
            }
            return OQS_ERROR;
        }
        ctx->dest_uri = OPENSSL_strdup(env_dest_uri);
        if (!ctx->dest_uri) {
            QKD_DEBUG("Error: Failed to allocate memory for dest_uri");
            // Clean up source_uri
            if (ctx->source_uri) {
                OPENSSL_free(ctx->source_uri);
                ctx->source_uri = NULL;
            }
            return OQS_ERROR;
        }
    }

    QKD_DEBUG("URIs initialized - source: %s, dest: %s", 
              ctx->source_uri, ctx->dest_uri);
    return OQS_SUCCESS;
}

int oqs_init_qkd_context(OQSX_KEY *oqsx_key, bool is_initiator) {
    int ret = OQS_SUCCESS;
    QKD_DEBUG("Initializing QKD context");

    // Return success if context already exists and role matches
    if (oqsx_key->qkd_ctx != NULL) {
#ifdef ETSI_014_API
        // Check status even for existing context
        if (!qkd_get_status(oqsx_key->qkd_ctx)) {
            QKD_DEBUG("Failed to get QKD status for existing context");
            goto err;
        }
#endif
        if (oqsx_key->qkd_ctx->is_initiator == is_initiator) {
            QKD_DEBUG("QKD context already initialized with correct role");
            return OQS_SUCCESS;
        }
        if (is_initiator && oqsx_key->comp_privkey) {
            QKD_DEBUG("QKD context exists with key - preserving for initiator");
            oqsx_key->qkd_ctx->is_initiator = true;
            return OQS_SUCCESS;
        }
#ifdef ETSI_004_API // TODO_QKD: check if we should do something for the ETSI_014_API case
        // Close existing context if role mismatch
        qkd_close(oqsx_key->qkd_ctx);
#endif
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
    } else {
        QKD_DEBUG("No existing QKD context found");
    }

    // Allocate new context
    oqsx_key->qkd_ctx = OPENSSL_malloc(sizeof(QKD_CTX));
    ON_ERR_SET_GOTO(oqsx_key->qkd_ctx == NULL, ret, OQS_ERROR, err);

    // Initialize context with clean state
    memset(oqsx_key->qkd_ctx, 0, sizeof(QKD_CTX));
    oqsx_key->qkd_ctx->is_initiator = is_initiator;

#ifdef ETSI_014_API
    // Initialize ETSI014 status fields to safe defaults
    oqsx_key->qkd_ctx->status.source_KME_ID = NULL;
    oqsx_key->qkd_ctx->status.target_KME_ID = NULL;
    oqsx_key->qkd_ctx->status.master_SAE_ID = NULL;
    oqsx_key->qkd_ctx->status.slave_SAE_ID = NULL;
#endif
    // Initialize URIs
    ret = qkd_init_uris(oqsx_key->qkd_ctx);
    if (ret != OQS_SUCCESS) {
        QKD_DEBUG("Failed to initialize QKD URIs");
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        goto err;
    }

    // Open QKD connection
#ifdef ETSI_004_API
    ret = qkd_open(oqsx_key->qkd_ctx);
    if (ret <= 0) {
        QKD_DEBUG("Failed to open QKD connection");
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        goto err;
    }
#elif defined(ETSI_014_API)
    // Here we load the URIs from the environment variables and check the status
    if (!qkd_get_status(oqsx_key->qkd_ctx)) {
        QKD_DEBUG("Failed to get QKD status for existing context");
        goto err;
    }
    ret = OQS_SUCCESS;
#endif

    QKD_DEBUG("QKD context initialized successfully as %s",
              is_initiator ? "initiator" : "responder");
    // print oqsx_key->qkd_ctx->is_initiator = is_initiator
    QKD_DEBUG("INIT: Initiator role: %d", oqsx_key->qkd_ctx->is_initiator);
err:
    return ret;
}
