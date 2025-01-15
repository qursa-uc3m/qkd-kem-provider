/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_ctx.c
 * OQS provider context management
 */

#include "oqs_ctx.h"
#include <openssl/err.h>
#include <openssl/params.h>

#define DEBUG_OQS

#ifdef NDEBUG
#define OQS_DEBUG(fmt, ...)
#else
#ifdef DEBUG_OQS
#define OQS_DEBUG(fmt, ...)                                                    \
    fprintf(stderr, "OQS DEBUG: %s:%d: " fmt "\n", __func__, __LINE__,         \
            ##__VA_ARGS__)
#else
#define OQS_DEBUG(fmt, ...)
#endif
#endif

OQS_CTX *oqs_init_context(const char *config_file) {
    OQS_CTX *ctx = OPENSSL_malloc(sizeof(OQS_CTX));
    if (!ctx) {
        OQS_DEBUG("Failed to allocate OQS context");
        return NULL;
    }

    // Initialize context with clean state
    memset(ctx, 0, sizeof(OQS_CTX));
    ctx->config_file = config_file;

    // Create new library context
    ctx->lib_ctx = OSSL_LIB_CTX_new();
    if (!ctx->lib_ctx) {
        OQS_DEBUG("Failed to create library context");
        goto err;
    }

    // Load configuration if provided
    if (config_file) {
        if (!OSSL_LIB_CTX_load_config(ctx->lib_ctx, config_file)) {
            OQS_DEBUG("Failed to load config file: %s", config_file);
            goto err;
        }
    }

    // Load default provider (needed for some operations)
    ctx->default_provider = OSSL_PROVIDER_load(ctx->lib_ctx, "default");
    if (!ctx->default_provider) {
        OQS_DEBUG("Failed to load default provider");
        goto err;
    }

    // Load OQS provider
    ctx->oqs_provider = OSSL_PROVIDER_load(ctx->lib_ctx, OQSPROVIDER_NAME);
    if (!ctx->oqs_provider) {
        OQS_DEBUG("Failed to load OQS provider");
        goto err;
    }

    ctx->initialized = 1;
    OQS_DEBUG("OQS context initialized successfully");
    return ctx;

err:
    oqs_free_context(ctx);
    return NULL;
}

void oqs_free_context(OQS_CTX *ctx) {
    if (!ctx) {
        return;
    }

    if (ctx->oqs_provider) {
        OSSL_PROVIDER_unload(ctx->oqs_provider);
    }
    
    if (ctx->default_provider) {
        OSSL_PROVIDER_unload(ctx->default_provider);
    }
    
    if (ctx->lib_ctx) {
        OSSL_LIB_CTX_free(ctx->lib_ctx);
    }

    OPENSSL_free(ctx);
    OQS_DEBUG("OQS context freed");
}

EVP_PKEY_CTX *oqs_get_pqc_ctx(OQS_CTX *ctx, const char *alg_name) {
    if (!ctx || !ctx->initialized || !alg_name) {
        OQS_DEBUG("Invalid context or algorithm name");
        return NULL;
    }

    EVP_PKEY_CTX *pqc_ctx = EVP_PKEY_CTX_new_from_name(ctx->lib_ctx, alg_name, OQSPROVIDER_PROPERTY_STRING);
    if (!pqc_ctx) {
        OQS_DEBUG("Failed to create PQC context for %s", alg_name);
        return NULL;
    }

    OQS_DEBUG("Created PQC context for %s", alg_name);
    return pqc_ctx;
}

EVP_PKEY *get_pqc_public_key(OQS_CTX *ctx, OQSX_KEY *key, const char *alg_name) {
    if (!ctx || !ctx->initialized || !key || !key->comp_pubkey) {
        OQS_DEBUG("Invalid context, key, or public key component");
        return NULL;
    }

    int idx_pq = 0;
    
    // Debug prints for size information
    OQS_DEBUG("Key sizes before adjustment:");
    OQS_DEBUG("  Total pubkeylen: %zu", key->pubkeylen);
    OQS_DEBUG("  KEM public key length: %zu", 
              key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key);
    OQS_DEBUG("  QKD part size: %d", QKD_KSID_SIZE);

    // Calculate actual PQC key length by subtracting QKD part
    size_t pqc_key_len = key->oqsx_provider_ctx.oqsx_qs_ctx.kem->length_public_key;
    OQS_DEBUG("Using PQC key length: %zu", pqc_key_len);

    // Create context for key import
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(ctx->lib_ctx,
                                                    alg_name,
                                                    OQSPROVIDER_PROPERTY_STRING);
    if (!kctx) {
        OQS_DEBUG("Failed to create key context");
        return NULL;
    }

    // Create parameter list
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                        key->comp_pubkey[idx_pq],
                                        pqc_key_len),  // Use PQC-specific length
        OSSL_PARAM_construct_end()
    };

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_fromdata_init(kctx) <= 0) {
        OQS_DEBUG("Failed to initialize key import");
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    // Import as public key
    if (EVP_PKEY_fromdata(kctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        OQS_DEBUG("Failed to import public key data");
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(kctx);
    OQS_DEBUG("Successfully created PQC public key");
    return pkey;
}