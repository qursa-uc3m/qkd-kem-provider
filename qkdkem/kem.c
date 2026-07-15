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

static int kem_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    QKDKEM_CTX *ctx = vctx;
    QKDKEM_KEY *key = vkey;

    (void)params;
    if (!ctx || !key || !qkdkem_key_up_ref(key))
        return 0;
    qkdkem_key_free(ctx->key);
    ctx->key = key;
    return 1;
}

static int qkd_encapsulate(QKDKEM_KEY *key, unsigned char id[QKD_KSID_SIZE],
                           unsigned char secret[QKD_KEY_SIZE])
{
    QKDKEM_QKD_SESSION *session = qkdkem_key_qkd(key, false);

    if (!session)
        return 0;
#ifdef QKD_KEY_ID_CH
    memcpy(id, key->qkd_id, QKD_KSID_SIZE);
    return qkdkem_qkd_offer_accept(session, key->qkd_id, secret);
#else
    return qkdkem_qkd_response_create(session, id, secret);
#endif
}

static int qkd_decapsulate(QKDKEM_KEY *key,
                           const unsigned char id[QKD_KSID_SIZE],
                           unsigned char secret[QKD_KEY_SIZE])
{
#ifdef QKD_KEY_ID_CH
    (void)id;
    if (key->has_qkd_key) {
        memcpy(secret, key->qkd_key, QKD_KEY_SIZE);
        return 1;
    }
    if (!key->qkd)
        return 0;
    return qkdkem_qkd_offer_finish(key->qkd, secret);
#else
    QKDKEM_QKD_SESSION *session = qkdkem_key_qkd(key, true);

    return session && qkdkem_qkd_response_accept(session, id, secret);
#endif
}

static int kem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                           unsigned char *secret, size_t *secretlen)
{
    QKDKEM_CTX *ctx = vctx;
    EVP_PKEY_CTX *inner = NULL;
    unsigned char qkd_id[QKD_KSID_SIZE];
    unsigned char qkd_secret[QKD_KEY_SIZE];
    size_t pq_out_len = 0;
    size_t pq_secret_len = 0;
    size_t out_capacity;
    size_t secret_capacity;
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

    if (!qkd_encapsulate(ctx->key, qkd_id, qkd_secret))
        goto done;
    if (EVP_PKEY_encapsulate(inner, out, &pq_out_len, secret, &pq_secret_len)
        <= 0)
        goto done;
    memcpy(out + pq_out_len, qkd_id, QKD_KSID_SIZE);
    memcpy(secret + pq_secret_len, qkd_secret, QKD_KEY_SIZE);
    *outlen = pq_out_len + QKD_KSID_SIZE;
    *secretlen = pq_secret_len + QKD_KEY_SIZE;
    ok = 1;

done:
    OPENSSL_cleanse(qkd_secret, sizeof(qkd_secret));
    EVP_PKEY_CTX_free(inner);
    return ok;
}

static int kem_decapsulate(void *vctx, unsigned char *secret, size_t *secretlen,
                           const unsigned char *in, size_t inlen)
{
    QKDKEM_CTX *ctx = vctx;
    EVP_PKEY_CTX *inner = NULL;
    unsigned char qkd_secret[QKD_KEY_SIZE];
    const unsigned char *qkd_id;
    size_t pq_in_len;
    size_t pq_secret_len = 0;
    size_t secret_capacity;
    int ok = 0;

    if (!ctx || !ctx->key || !ctx->key->pq_key || !ctx->key->has_private
        || !secretlen || !in || inlen <= QKD_KSID_SIZE)
        return 0;
    pq_in_len = inlen - QKD_KSID_SIZE;
    qkd_id = in + pq_in_len;
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
    if (!qkd_decapsulate(ctx->key, qkd_id, qkd_secret))
        goto done;
    if (EVP_PKEY_decapsulate(inner, secret, &pq_secret_len, in, pq_in_len) <= 0)
        goto done;
    memcpy(secret + pq_secret_len, qkd_secret, QKD_KEY_SIZE);
    *secretlen = pq_secret_len + QKD_KEY_SIZE;
    ok = 1;

done:
    OPENSSL_cleanse(qkd_secret, sizeof(qkd_secret));
    EVP_PKEY_CTX_free(inner);
    return ok;
}

const OSSL_DISPATCH qkdkem_kem_functions[]
    = {{OSSL_FUNC_KEM_NEWCTX, (void (*)(void))kem_newctx},
       {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))kem_init},
       {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))kem_encapsulate},
       {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))kem_init},
       {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))kem_decapsulate},
       {OSSL_FUNC_KEM_FREECTX, (void (*)(void))kem_freectx},
       {0, NULL}};
