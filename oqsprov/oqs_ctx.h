/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_ctx.h
 * OQS provider context management
 */

#ifndef OQS_CTX_H
#define OQS_CTX_H

#include <string.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include "oqs_prov.h"

/* Provider configuration */
#define OQSPROVIDER_NAME "oqsprovider"
#define OQSPROVIDER_PROPERTY_STRING "provider=oqsprovider"

// Structure to hold OQS provider context
typedef struct oqs_ctx_st {
    OSSL_LIB_CTX *lib_ctx;
    OSSL_PROVIDER *oqs_provider;
    OSSL_PROVIDER *default_provider;
    const char *config_file;
    int initialized;
} OQS_CTX;

// Initialize OQS provider context
OQS_CTX *oqs_init_context(const char *config_file);

// Free OQS provider context
void oqs_free_context(OQS_CTX *ctx);

// Get PQC key context
EVP_PKEY_CTX *oqs_get_pqc_ctx(OQS_CTX *ctx, const char *alg_name);

// Helper function to get PQC public key from OQSX_KEY
EVP_PKEY *get_pqc_public_key(OQS_CTX *ctx, OQSX_KEY *key, const char *alg_name);

EVP_PKEY *get_pqc_private_key(OQS_CTX *ctx, OQSX_KEY *key, const char *alg_name);

#endif /* OQS_CTX_H */