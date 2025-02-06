/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_ctx.c
 * QKD context initialization
 */
#include "oqs_qkd_ctx.h"

//#define DEBUG_QKD

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
    if (!ctx) {
        QKD_DEBUG("Invalid context");
        return OQS_ERROR;
    }

    // Get base hostnames only
    const char *master_kme = getenv("QKD_MASTER_KME_HOSTNAME");
    const char *slave_kme = getenv("QKD_SLAVE_KME_HOSTNAME");
    const char *master_sae = getenv("QKD_MASTER_SAE");
    const char *slave_sae = getenv("QKD_SLAVE_SAE");

    if (!master_kme || !slave_kme || !master_sae || !slave_sae) {
        QKD_DEBUG("Required QuKayDee environment variables not set");
        return OQS_ERROR;
    }

    // Store base URLs without path components
    ctx->master_kme = OPENSSL_strdup(master_kme);
    ctx->slave_kme = OPENSSL_strdup(slave_kme);
    ctx->master_sae = OPENSSL_strdup(master_sae);
    ctx->slave_sae = OPENSSL_strdup(slave_sae);

    if (!ctx->master_kme || !ctx->slave_kme || 
        !ctx->master_sae || !ctx->slave_sae) {
        QKD_DEBUG("Failed to allocate KME or SAE strings");
        goto err;
    }

    // Assign base URLs and SAE IDs based on role
    if (ctx->is_initiator) {
        ctx->source_uri = ctx->master_kme;
        ctx->dest_uri = ctx->slave_kme;
        ctx->sae_id = ctx->slave_sae;
    } else {
        ctx->source_uri = ctx->slave_kme;
        ctx->dest_uri = ctx->master_kme;
        ctx->sae_id = ctx->master_sae;
    }

    QKD_DEBUG("KME configuration initialized:");
    QKD_DEBUG("Source KME: %s", ctx->source_uri);
    QKD_DEBUG("SAE ID: %s", ctx->sae_id);

    return OQS_SUCCESS;

err:
    OPENSSL_free(ctx->master_kme);
    OPENSSL_free(ctx->slave_kme);
    OPENSSL_free(ctx->master_sae);
    OPENSSL_free(ctx->slave_sae);
    ctx->master_kme = NULL;
    ctx->slave_kme = NULL; 
    ctx->master_sae = NULL;
    ctx->slave_sae = NULL;
    ctx->source_uri = NULL;
    ctx->dest_uri = NULL;
    ctx->sae_id = NULL;
    return OQS_ERROR;
}

int oqs_init_qkd_context(OQSX_KEY *oqsx_key, bool is_initiator) {
    int ret = OQS_SUCCESS;

    QKD_DEBUG("Initializing QKD context");

    // Return success if context already exists and role matches
     if (oqsx_key->qkd_ctx != NULL) {
        #ifdef ETSI_014_API
        #ifdef DEBUG_QKD
        if (!qkd_get_status(oqsx_key->qkd_ctx)) {
            QKD_DEBUG("Failed to get QKD status for existing context");
            return OQS_ERROR;
        }
        #endif /* NDEBUG */
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

        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
    }

    // Allocate and initialize new context
    oqsx_key->qkd_ctx = OPENSSL_malloc(sizeof(QKD_CTX));
    if (oqsx_key->qkd_ctx == NULL) {
        QKD_DEBUG("Failed to allocate QKD context");
        return OQS_ERROR;
    }

    // Initialize context with clean state
    memset(oqsx_key->qkd_ctx, 0, sizeof(QKD_CTX));
    oqsx_key->qkd_ctx->is_initiator = is_initiator;

    // Initialize URIs - this must be done before status check
    ret = qkd_init_uris(oqsx_key->qkd_ctx);
    if (ret != OQS_SUCCESS) {
        QKD_DEBUG("Failed to initialize QKD URIs");
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        return OQS_ERROR;
    }

    #ifdef ETSI_014_API 
    // After URIs are set, initialize ETSI014 specific fields and check status
    qkd_status_t *status = &oqsx_key->qkd_ctx->status;
    status->source_KME_ID = NULL;
    status->target_KME_ID = NULL;
    status->master_SAE_ID = NULL;
    status->slave_SAE_ID = NULL;
    
    // Initialize and validate status with KME
    #ifdef DEBUG_QKD
    if (!qkd_get_status(oqsx_key->qkd_ctx)) {
        QKD_DEBUG("Failed to get initial QKD status");
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        return OQS_ERROR;
    }
    #endif /* NDEBUG */
    #endif

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
    #ifdef DEBUG_QKD
    if (!qkd_get_status(oqsx_key->qkd_ctx)) {
        QKD_DEBUG("Failed to get QKD status for existing context");
        goto err;
    }
    #endif /* NDEBUG */
    ret = OQS_SUCCESS;
    #endif

    QKD_DEBUG("QKD context initialized successfully as %s",
              is_initiator ? "initiator" : "responder");
    // print oqsx_key->qkd_ctx->is_initiator = is_initiator
    QKD_DEBUG("INIT: Initiator role: %d", oqsx_key->qkd_ctx->is_initiator);

    return OQS_SUCCESS;

err:
    return ret;
}
