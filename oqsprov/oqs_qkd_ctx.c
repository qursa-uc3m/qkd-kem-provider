/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_ctx.c
 * QKD context initialization
 */
#include "oqs_qkd_ctx.h"

// #define DEBUG_QKD

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

#ifdef ETSI_004_API

    const char *source_uri = getenv("QKD_SOURCE_URI");
    const char *dest_uri = getenv("QKD_DEST_URI");

    if (!source_uri || !dest_uri) {
        QKD_DEBUG("ETSI 004: QKD_SOURCE_URI and QKD_DEST_URI must be set");
        return OQS_ERROR;
    }

    QKD_DEBUG("ETSI 004: Using URIs from environment: source=%s, dest=%s", 
              source_uri, dest_uri);

    // Store the URIs directly
    ctx->source_uri = OPENSSL_strdup(source_uri);
    ctx->dest_uri = OPENSSL_strdup(dest_uri);

    if (!ctx->source_uri || !ctx->dest_uri) {
        QKD_DEBUG("ETSI 004: Failed to allocate URI strings");
        goto err;
    }

#else
    // For ETSI 014, use the hostname-based environment variables
    const char *master_kme = getenv("QKD_MASTER_KME_HOSTNAME");
    const char *slave_kme = getenv("QKD_SLAVE_KME_HOSTNAME");
    const char *master_sae = getenv("QKD_MASTER_SAE");
    const char *slave_sae = getenv("QKD_SLAVE_SAE");

    if (!master_kme || !slave_kme || !master_sae || !slave_sae) {
        QKD_DEBUG("ETSI 014: Required environment variables not set");
        return OQS_ERROR;
    }

    QKD_DEBUG("ETSI 014: Using hostnames: master_kme=%s, slave_kme=%s", 
              master_kme, slave_kme);

    // Store hostnames
    ctx->master_kme = OPENSSL_strdup(master_kme);
    ctx->slave_kme = OPENSSL_strdup(slave_kme);
    ctx->master_sae = OPENSSL_strdup(master_sae);
    ctx->slave_sae = OPENSSL_strdup(slave_sae);

    if (!ctx->master_kme || !ctx->slave_kme || !ctx->master_sae || !ctx->slave_sae) {
        QKD_DEBUG("ETSI 014: Failed to allocate KME or SAE strings");
        goto err;
    }

    // Set URIs based on role
    if (ctx->is_initiator) {
        ctx->source_uri = ctx->master_kme;
        ctx->dest_uri = ctx->slave_kme;
        ctx->sae_id = ctx->slave_sae;
    } else {
        ctx->source_uri = ctx->slave_kme;
        ctx->dest_uri = ctx->master_kme;
        ctx->sae_id = ctx->master_sae;
    }
#endif

    QKD_DEBUG("Final configuration: source_uri=%s, dest_uri=%s", 
              ctx->source_uri ? ctx->source_uri : "NULL", 
              ctx->dest_uri ? ctx->dest_uri : "NULL");

    return OQS_SUCCESS;

err:
#ifdef ETSI_004_API
    // For ETSI 004: clean up directly allocated URIs
    if (ctx->source_uri) { OPENSSL_free(ctx->source_uri); ctx->source_uri = NULL; }
    if (ctx->dest_uri) { OPENSSL_free(ctx->dest_uri); ctx->dest_uri = NULL; }
#else
    // For ETSI 014: clean up KME/SAE strings (URIs point to these, so they'll be cleaned too)
    if (ctx->master_kme) { OPENSSL_free(ctx->master_kme); ctx->master_kme = NULL; }
    if (ctx->slave_kme) { OPENSSL_free(ctx->slave_kme); ctx->slave_kme = NULL; }
    if (ctx->master_sae) { OPENSSL_free(ctx->master_sae); ctx->master_sae = NULL; }
    if (ctx->slave_sae) { OPENSSL_free(ctx->slave_sae); ctx->slave_sae = NULL; }
    ctx->source_uri = NULL;
    ctx->dest_uri = NULL;
    ctx->sae_id = NULL;
#endif
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

#ifdef ETSI_004_API
    /* Initialize QoS parameters for ETSI 004 */
    
    // Define metadata max size if not already defined
    #ifndef QKD_METADATA_MAX_SIZE
    #define QKD_METADATA_MAX_SIZE 1024
    #endif
    
    // Set default QoS parameters using the correct field names (lowercase for some)
    oqsx_key->qkd_ctx->qos.Key_chunk_size = QKD_KEY_SIZE;
    oqsx_key->qkd_ctx->qos.Timeout = 60000;
    oqsx_key->qkd_ctx->qos.Priority = 0;
    oqsx_key->qkd_ctx->qos.Max_bps = 40000;
    oqsx_key->qkd_ctx->qos.Min_bps = 5000;
    oqsx_key->qkd_ctx->qos.Jitter = 10;
    oqsx_key->qkd_ctx->qos.TTL = 3600;
    strcpy(oqsx_key->qkd_ctx->qos.Metadata_mimetype, "application/json");
    
    if (!oqsx_key->qkd_ctx->qos.Metadata_mimetype) {
        QKD_DEBUG("Memory allocation for metadata mimetype failed");
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        return OQS_ERROR;
    }
    
    // Override with environment variables if present
    const char *env_chunk_size = getenv("QKD_QOS_KEY_CHUNK_SIZE");
    const char *env_timeout = getenv("QKD_QOS_TIMEOUT");
    const char *env_priority = getenv("QKD_QOS_PRIORITY");
    const char *env_max_bps = getenv("QKD_QOS_MAX_BPS");
    const char *env_min_bps = getenv("QKD_QOS_MIN_BPS");
    const char *env_jitter = getenv("QKD_QOS_JITTER");
    const char *env_ttl = getenv("QKD_QOS_TTL");
    
    if (env_chunk_size) oqsx_key->qkd_ctx->qos.Key_chunk_size = atoi(env_chunk_size);
    if (env_timeout) oqsx_key->qkd_ctx->qos.Timeout = atoi(env_timeout);
    if (env_priority) oqsx_key->qkd_ctx->qos.Priority = atoi(env_priority);
    if (env_max_bps) oqsx_key->qkd_ctx->qos.Max_bps = atoi(env_max_bps);
    if (env_min_bps) oqsx_key->qkd_ctx->qos.Min_bps = atoi(env_min_bps);
    if (env_jitter) oqsx_key->qkd_ctx->qos.Jitter = atoi(env_jitter);
    if (env_ttl) oqsx_key->qkd_ctx->qos.TTL = atoi(env_ttl);
    
    // Initialize metadata structure
    oqsx_key->qkd_ctx->metadata.Metadata_size = QKD_METADATA_MAX_SIZE;
    oqsx_key->qkd_ctx->metadata.Metadata_buffer = OPENSSL_malloc(QKD_METADATA_MAX_SIZE);
    if (!oqsx_key->qkd_ctx->metadata.Metadata_buffer) {
        QKD_DEBUG("Memory allocation for metadata buffer failed");
        OPENSSL_free(oqsx_key->qkd_ctx->qos.Metadata_mimetype);
        OPENSSL_free(oqsx_key->qkd_ctx);
        oqsx_key->qkd_ctx = NULL;
        return OQS_ERROR;
    }
    memset(oqsx_key->qkd_ctx->metadata.Metadata_buffer, 0, QKD_METADATA_MAX_SIZE);
    
    // Do NOT call qkd_open() here
    // For ETSI 004:
    // - Alice will call qkd_open() during key generation (oqsx_key_gen_qkd)
    // - Bob will call qkd_open() during encapsulation (oqs_qkd_get_encaps_key)
    oqsx_key->qkd_ctx->is_connected = false;
    QKD_DEBUG("ETSI 004: Context initialized, connection deferred to key generation/encapsulation");
#endif

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

    QKD_DEBUG("QKD context initialized successfully as %s",
              is_initiator ? "initiator" : "responder");
    QKD_DEBUG("INIT: Initiator role: %d", oqsx_key->qkd_ctx->is_initiator);
    QKD_DEBUG("INIT: Connection will be established later during key operations");

    return OQS_SUCCESS;
}
