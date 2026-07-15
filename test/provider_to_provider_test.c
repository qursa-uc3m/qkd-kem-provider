/* SPDX-License-Identifier: MIT */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ETSI_004_API
#    ifdef QKDKEM_QKD_FLAT_HEADERS
#        include <etsi014/api.h>
#    else
#        include <qkd-etsi-api-c-wrapper/etsi014/api.h>
#    endif

static char *duplicate_text(const char *text)
{
    size_t length = strlen(text) + 1;
    char *copy = malloc(length);

    if (copy)
        memcpy(copy, text, length);
    return copy;
}

static uint32_t malformed_get_key(const char *kme_hostname,
                                  const char *slave_sae_id,
                                  qkd_key_request_t *request,
                                  qkd_key_container_t *container)
{
    static const char oversized_base64[]
        = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    qkd_key_t *key;

    (void)kme_hostname;
    (void)slave_sae_id;
    (void)request;
    if (!container)
        return QKD_STATUS_SERVER_ERROR;
    container->keys = calloc(1, sizeof(*container->keys));
    if (!container->keys)
        return QKD_STATUS_SERVER_ERROR;
    container->key_count = 1;
    key = &container->keys[0];
    key->key_ID = duplicate_text("12345678-1234-4234-8234-123456789abc");
    key->key = duplicate_text(oversized_base64);
    if (!key->key_ID || !key->key)
        return QKD_STATUS_SERVER_ERROR;
    return QKD_STATUS_OK;
}

static const struct qkd_014_backend malformed_backend
    = {.name = "malformed-test", .get_key = malformed_get_key};
#endif

static int fail(const char *operation)
{
    fprintf(stderr, "%s failed\n", operation);
    ERR_print_errors_fp(stderr);
    return 0;
}

static int count_group(const OSSL_PARAM params[], void *arg)
{
    const OSSL_PARAM *name
        = OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);
    size_t *count = arg;

    if (!name || name->data_type != OSSL_PARAM_UTF8_STRING)
        return 0;
    if (strncmp(name->data, "qkd_", 4) == 0)
        (*count)++;
    return 1;
}

int main(void)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *qkd_provider = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *private_key = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY *rejected_key = NULL;
    unsigned char *encoded = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *encapsulated = NULL;
    unsigned char *decapsulated = NULL;
    size_t encoded_len;
    size_t ciphertext_len = 0;
    size_t encapsulated_len = 0;
    size_t decapsulated_len = 0;
    size_t group_count = 0;
    int ok = 0;
#ifndef ETSI_004_API
    const struct qkd_014_backend *original_backend = NULL;
#endif

    libctx = OSSL_LIB_CTX_new();
    if (!libctx)
        return !fail("OSSL_LIB_CTX_new");
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    qkd_provider = OSSL_PROVIDER_load(libctx, "qkdkemprovider");
    if (!default_provider || !qkd_provider)
        goto done;

    if (!OSSL_PROVIDER_get_capabilities(qkd_provider, "TLS-GROUP", count_group,
                                        &group_count)
        || group_count != 3) {
        fprintf(stderr, "expected 3 dynamically available groups, got %zu\n",
                group_count);
        goto done;
    }

    ctx = EVP_PKEY_CTX_new_from_name(libctx, "qkd_mlkem768", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_generate(ctx, &private_key) <= 0) {
        fail("hybrid key generation");
        goto done;
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, private_key, NULL);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) > 0
        || ERR_peek_last_error() == 0) {
        fprintf(stderr, "generated-key encapsulation was not rejected\n");
        goto done;
    }
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

#if defined(QKD_KEY_ID_CH) && !defined(ETSI_004_API)
    original_backend = get_active_014_backend();
    register_qkd_014_backend(&malformed_backend);
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "qkd_mlkem768", NULL);
    if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_generate(ctx, &rejected_key) > 0) {
        fprintf(stderr, "oversized KME key was not rejected\n");
        goto done;
    }
    register_qkd_014_backend(original_backend);
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
#endif

    encoded_len = EVP_PKEY_get1_encoded_public_key(private_key, &encoded);
    if (!encoded_len) {
        fail("public key export");
        goto done;
    }
    ctx = EVP_PKEY_CTX_new_from_name(libctx, "qkd_mlkem768", NULL);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) <= 0) {
        fail("public key import initialization");
        goto done;
    }
    {
        OSSL_PARAM params[] = {OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                       encoded, encoded_len),
                               OSSL_PARAM_END};
        if (EVP_PKEY_fromdata(ctx, &public_key, EVP_PKEY_PUBLIC_KEY, params)
            <= 0) {
            fail("public key import");
            goto done;
        }
    }
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, public_key, NULL);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_len, NULL,
                                &encapsulated_len)
               <= 0)
        goto done;
    if (EVP_PKEY_get_size(public_key) != (int)ciphertext_len) {
        fprintf(stderr, "reported maximum size does not match ciphertext\n");
        goto done;
    }
    ciphertext = OPENSSL_malloc(ciphertext_len);
    encapsulated = OPENSSL_malloc(encapsulated_len);
#if !defined(QKD_KEY_ID_CH) && !defined(ETSI_004_API)
    original_backend = get_active_014_backend();
    register_qkd_014_backend(&malformed_backend);
    if (!ciphertext || !encapsulated
        || EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, encapsulated,
                                &encapsulated_len)
               > 0) {
        fprintf(stderr, "oversized KME key was not rejected\n");
        goto done;
    }
    register_qkd_014_backend(original_backend);
    ERR_clear_error();
#endif
    if (!ciphertext || !encapsulated
        || EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, encapsulated,
                                &encapsulated_len)
               <= 0) {
        fail("provider-to-provider encapsulation");
        goto done;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, private_key, NULL);
#ifdef QKD_KEY_ID_CH
    ciphertext[ciphertext_len - 1] ^= 1;
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, NULL, &decapsulated_len, ciphertext,
                                ciphertext_len)
               > 0
        || ERR_peek_last_error() == 0) {
        fprintf(stderr, "mismatched QKD identifier was not rejected\n");
        goto done;
    }
    ciphertext[ciphertext_len - 1] ^= 1;
    ERR_clear_error();
    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, private_key, NULL);
#endif
    if (!ctx || EVP_PKEY_decapsulate_init(ctx, NULL) <= 0
        || EVP_PKEY_decapsulate(ctx, NULL, &decapsulated_len, ciphertext,
                                ciphertext_len)
               <= 0)
        goto done;
    decapsulated = OPENSSL_malloc(decapsulated_len);
    if (!decapsulated
        || EVP_PKEY_decapsulate(ctx, decapsulated, &decapsulated_len,
                                ciphertext, ciphertext_len)
               <= 0) {
        fail("provider-to-provider decapsulation");
        goto done;
    }
    ok = encapsulated_len == decapsulated_len
         && CRYPTO_memcmp(encapsulated, decapsulated, encapsulated_len) == 0;
    if (!ok)
        fprintf(stderr, "shared secrets differ\n");

done:
#ifndef ETSI_004_API
    if (original_backend)
        register_qkd_014_backend(original_backend);
#endif
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(rejected_key);
    OPENSSL_free(encoded);
    OPENSSL_free(ciphertext);
    OPENSSL_clear_free(encapsulated, encapsulated_len);
    OPENSSL_clear_free(decapsulated, decapsulated_len);
    OSSL_PROVIDER_unload(qkd_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return ok ? 0 : 1;
}
