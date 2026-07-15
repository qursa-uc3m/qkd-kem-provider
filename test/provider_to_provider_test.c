/* SPDX-License-Identifier: MIT */
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>

#include <stdio.h>
#include <string.h>

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
    ciphertext = OPENSSL_malloc(ciphertext_len);
    encapsulated = OPENSSL_malloc(encapsulated_len);
    if (!ciphertext || !encapsulated
        || EVP_PKEY_encapsulate(ctx, ciphertext, &ciphertext_len, encapsulated,
                                &encapsulated_len)
               <= 0) {
        fail("provider-to-provider encapsulation");
        goto done;
    }

    EVP_PKEY_CTX_free(ctx);
    ctx = EVP_PKEY_CTX_new_from_pkey(libctx, private_key, NULL);
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
    if (!ok)
        ERR_print_errors_fp(stderr);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(private_key);
    EVP_PKEY_free(public_key);
    OPENSSL_free(encoded);
    OPENSSL_free(ciphertext);
    OPENSSL_clear_free(encapsulated, encapsulated_len);
    OPENSSL_clear_free(decapsulated, decapsulated_len);
    OSSL_PROVIDER_unload(qkd_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return ok ? 0 : 1;
}
