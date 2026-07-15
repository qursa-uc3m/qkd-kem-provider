/* SPDX-License-Identifier: MIT */
#include "internal.h"

#include <string.h>

typedef struct {
    QKDKEM_PROV_CTX *provctx;
    QKDKEM_KEY *key;
} QKDKEM_CTX;

static void *kem_newctx(void *provctx)
{
    QKDKEM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx)
        ctx->provctx = provctx;
    return ctx;
}

static void kem_freectx(void *vctx)
{
    QKDKEM_CTX *ctx = vctx;

    if (!ctx)
        return;
    qkdkem_key_free(ctx->key);
    OPENSSL_free(ctx);
}

static int kem_set_key(QKDKEM_CTX *ctx, QKDKEM_KEY *key)
{
    if (!ctx || !key || !qkdkem_key_up_ref(key))
        return 0;
    qkdkem_key_free(ctx->key);
    ctx->key = key;
    return 1;
}

static int kem_encapsulate_init(void *vctx, void *vkey,
                                const OSSL_PARAM params[])
{
    QKDKEM_KEY *key = vkey;

    (void)params;
    if (!key || key->has_private) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "encapsulation requires an imported peer public key");
        return 0;
    }
    return kem_set_key(vctx, key);
}

static int kem_decapsulate_init(void *vctx, void *vkey,
                                const OSSL_PARAM params[])
{
    QKDKEM_KEY *key = vkey;

    (void)params;
    if (!key || !key->has_private) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_KEY,
                       "decapsulation requires a generated private key");
        return 0;
    }
    return kem_set_key(vctx, key);
}

static int qkd_encapsulate(QKDKEM_KEY *key, unsigned char id[QKD_KSID_SIZE],
                           unsigned char secret[QKD_KEY_SIZE])
{
    QKDKEM_QKD_SESSION *session;
    int ok = 0;

    if (!key || !CRYPTO_THREAD_write_lock(key->lock))
        return 0;
    session = qkdkem_key_qkd(key, false);
    if (!session)
        goto done;
#ifdef QKD_KEY_ID_CH
    memcpy(id, key->qkd_id, QKD_KSID_SIZE);
    ok = qkdkem_qkd_offer_accept(session, key->qkd_id, secret);
#else
    ok = qkdkem_qkd_response_create(session, id, secret);
#endif

done:
    CRYPTO_THREAD_unlock(key->lock);
    return ok;
}

static int qkd_decapsulate(QKDKEM_KEY *key,
                           const unsigned char id[QKD_KSID_SIZE],
                           unsigned char secret[QKD_KEY_SIZE])
{
    int ok = 0;

    if (!key || !CRYPTO_THREAD_write_lock(key->lock))
        return 0;
#ifdef QKD_KEY_ID_CH
    if (CRYPTO_memcmp(id, key->qkd_id, QKD_KSID_SIZE) != 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "QKD key identifier does not match the key share");
    } else if (key->has_qkd_key) {
        memcpy(secret, key->qkd_key, QKD_KEY_SIZE);
        ok = 1;
    } else if (key->qkd) {
        ok = qkdkem_qkd_offer_finish(key->qkd, secret);
    }
#else
    QKDKEM_QKD_SESSION *session = qkdkem_key_qkd(key, true);

    ok = session && qkdkem_qkd_response_accept(session, id, secret);
#endif

    CRYPTO_THREAD_unlock(key->lock);
    return ok;
}

static int kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{
    QKDKEM_CTX *ctx = vctx;
    EVP_PKEY_CTX *inner = NULL;
    unsigned char qkd_id[QKD_KSID_SIZE] = {0};
    unsigned char qkd_secret[QKD_KEY_SIZE] = {0};
    size_t pq_out_len = 0;
    size_t pq_secret_len = 0;
    size_t out_capacity;
    size_t secret_capacity;
    int pq_complete = 0;
    int ok = 0;

    if (!ctx || !ctx->key || !ctx->key->pq_key || !outlen || !secretlen)
        return 0;
    inner = EVP_PKEY_CTX_new_from_pkey(ctx->provctx->libctx, ctx->key->pq_key,
                                       NULL);
    if (!inner || EVP_PKEY_encapsulate_init(inner, NULL) <= 0
        || EVP_PKEY_encapsulate(inner, NULL, &pq_out_len, NULL, &pq_secret_len)
               <= 0
        || pq_out_len > SIZE_MAX - QKD_KSID_SIZE
        || pq_secret_len > SIZE_MAX - QKD_KEY_SIZE)
        goto done;

    out_capacity = *outlen;
    secret_capacity = *secretlen;
    *outlen = pq_out_len + QKD_KSID_SIZE;
    *secretlen = pq_secret_len + QKD_KEY_SIZE;
    if (!out && !secret) {
        ok = 1;
        goto done;
    }
    if (!out || !secret || out_capacity < *outlen
        || secret_capacity < *secretlen)
        goto done;

    if (EVP_PKEY_encapsulate(inner, out, &pq_out_len, secret, &pq_secret_len)
        <= 0)
        goto done;
    pq_complete = 1;
    if (!qkd_encapsulate(ctx->key, qkd_id, qkd_secret))
        goto done;
    memcpy(out + pq_out_len, qkd_id, QKD_KSID_SIZE);
    memcpy(secret + pq_secret_len, qkd_secret, QKD_KEY_SIZE);
    *outlen = pq_out_len + QKD_KSID_SIZE;
    *secretlen = pq_secret_len + QKD_KEY_SIZE;
    ok = 1;

done:
    if (!ok && pq_complete)
        OPENSSL_cleanse(secret, pq_secret_len);
    OPENSSL_cleanse(qkd_secret, sizeof(qkd_secret));
    EVP_PKEY_CTX_free(inner);
    return ok;
}

static int kem_decapsulate(void *vctx, unsigned char *secret, size_t *secretlen,
                           const unsigned char *in, size_t inlen)
{
    QKDKEM_CTX *ctx = vctx;
    EVP_PKEY_CTX *inner = NULL;
    unsigned char qkd_secret[QKD_KEY_SIZE] = {0};
    const unsigned char *qkd_id;
    size_t pq_in_len;
    size_t pq_secret_len = 0;
    size_t secret_capacity;
    int pq_complete = 0;
    int ok = 0;

    if (!ctx || !ctx->key || !ctx->key->pq_key || !ctx->key->has_private
        || !secretlen || !in || inlen <= QKD_KSID_SIZE)
        return 0;
    pq_in_len = inlen - QKD_KSID_SIZE;
    qkd_id = in + pq_in_len;
#ifdef QKD_KEY_ID_CH
    if (CRYPTO_memcmp(qkd_id, ctx->key->qkd_id, QKD_KSID_SIZE) != 0) {
        ERR_raise_data(ERR_LIB_PROV, PROV_R_INVALID_DATA,
                       "QKD key identifier does not match the key share");
        return 0;
    }
#endif
    inner = EVP_PKEY_CTX_new_from_pkey(ctx->provctx->libctx, ctx->key->pq_key,
                                       NULL);
    if (!inner || EVP_PKEY_decapsulate_init(inner, NULL) <= 0
        || EVP_PKEY_decapsulate(inner, NULL, &pq_secret_len, in, pq_in_len) <= 0
        || pq_secret_len > SIZE_MAX - QKD_KEY_SIZE)
        goto done;

    secret_capacity = *secretlen;
    *secretlen = pq_secret_len + QKD_KEY_SIZE;
    if (!secret) {
        ok = 1;
        goto done;
    }
    if (secret_capacity < *secretlen)
        goto done;
    if (EVP_PKEY_decapsulate(inner, secret, &pq_secret_len, in, pq_in_len) <= 0)
        goto done;
    pq_complete = 1;
    if (!qkd_decapsulate(ctx->key, qkd_id, qkd_secret))
        goto done;
    memcpy(secret + pq_secret_len, qkd_secret, QKD_KEY_SIZE);
    *secretlen = pq_secret_len + QKD_KEY_SIZE;
    ok = 1;

done:
    if (!ok && pq_complete)
        OPENSSL_cleanse(secret, pq_secret_len);
    OPENSSL_cleanse(qkd_secret, sizeof(qkd_secret));
    EVP_PKEY_CTX_free(inner);
    return ok;
}

const OSSL_DISPATCH qkdkem_kem_functions[]
    = {{OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kem_newctx},
       {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kem_encapsulate_init},
       {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kem_encapsulate},
       {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kem_decapsulate_init},
       {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kem_decapsulate},
       {OSSL_FUNC_KEM_FREECTX, (void (*)(void))kem_freectx},
       {0, NULL}};
