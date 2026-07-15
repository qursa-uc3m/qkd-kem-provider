/* SPDX-License-Identifier: MIT */
#include "internal.h"

#include <openssl/core_names.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    QKDKEM_PROV_CTX *provctx;
    const QKDKEM_ALGORITHM *algorithm;
    int selection;
} QKDKEM_GEN_CTX;

QKDKEM_KEY *qkdkem_key_new(QKDKEM_PROV_CTX *provctx,
                           const QKDKEM_ALGORITHM *algorithm)
{
    QKDKEM_KEY *key;

    if (!provctx || !algorithm)
        return NULL;
    key = OPENSSL_zalloc(sizeof(*key));
    if (!key)
        return NULL;
    key->lock = CRYPTO_THREAD_lock_new();
    if (!key->lock) {
        OPENSSL_free(key);
        return NULL;
    }
    key->provctx = provctx;
    key->algorithm = algorithm;
    atomic_init(&key->references, 1);
    return key;
}

int qkdkem_key_up_ref(QKDKEM_KEY *key)
{
    int previous;

    if (!key)
        return 0;
    previous
        = atomic_fetch_add_explicit(&key->references, 1, memory_order_relaxed);
    return previous > 0;
}

void qkdkem_key_free(void *keydata)
{
    QKDKEM_KEY *key = keydata;

    if (!key)
        return;
    if (atomic_fetch_sub_explicit(&key->references, 1, memory_order_acq_rel)
        != 1)
        return;
    EVP_PKEY_free(key->pq_key);
    qkdkem_qkd_session_free(key->qkd);
    OPENSSL_cleanse(key->qkd_key, sizeof(key->qkd_key));
    CRYPTO_THREAD_lock_free(key->lock);
    OPENSSL_free(key);
}

QKDKEM_QKD_SESSION *qkdkem_key_qkd(QKDKEM_KEY *key, bool initiator)
{
    if (!key)
        return NULL;
    if (key->qkd)
        return key->qkd;
    key->qkd = qkdkem_qkd_session_new(initiator);
    return key->qkd;
}

int qkdkem_key_public_bytes(const QKDKEM_KEY *key, unsigned char **out,
                            size_t *outlen)
{
    unsigned char *pq_public = NULL;
    unsigned char *encoded = NULL;
    size_t pq_public_len;

    if (!key || !key->pq_key || !out || !outlen)
        return 0;
    pq_public_len = EVP_PKEY_get1_encoded_public_key(key->pq_key, &pq_public);
    if (!pq_public_len || pq_public_len > SIZE_MAX - QKD_KSID_SIZE)
        goto error;
    encoded = OPENSSL_malloc(pq_public_len + QKD_KSID_SIZE);
    if (!encoded)
        goto error;
    memcpy(encoded, pq_public, pq_public_len);
    memcpy(encoded + pq_public_len, key->qkd_id, QKD_KSID_SIZE);
    *out = encoded;
    *outlen = pq_public_len + QKD_KSID_SIZE;
    OPENSSL_free(pq_public);
    return 1;

error:
    OPENSSL_free(pq_public);
    OPENSSL_free(encoded);
    return 0;
}

static EVP_PKEY *import_inner_public(QKDKEM_KEY *key,
                                     const unsigned char *encoded,
                                     size_t encoded_len)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pq_key = NULL;
    OSSL_PARAM params[2];
    size_t i;
    const char *properties = getenv("QKDKEM_INNER_PROPERTIES");

    if (!properties || !*properties)
        properties = "provider!=qkdkemprovider";

    for (i = 0; i < QKDKEM_INNER_COUNT && key->algorithm->inner_names[i]; i++) {
        ctx = EVP_PKEY_CTX_new_from_name(
            key->provctx->libctx, key->algorithm->inner_names[i], properties);
        if (!ctx) {
            ERR_clear_error();
            continue;
        }
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_PUB_KEY, (void *)encoded, encoded_len);
        params[1] = OSSL_PARAM_construct_end();
        if (EVP_PKEY_fromdata_init(ctx) > 0
            && EVP_PKEY_fromdata(ctx, &pq_key, EVP_PKEY_PUBLIC_KEY, params)
                   > 0) {
            EVP_PKEY_CTX_free(ctx);
            return pq_key;
        }
        EVP_PKEY_CTX_free(ctx);
        ERR_clear_error();

        ctx = EVP_PKEY_CTX_new_from_name(
            key->provctx->libctx, key->algorithm->inner_names[i], properties);
        if (!ctx)
            continue;
        params[0] = OSSL_PARAM_construct_octet_string(
            OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, (void *)encoded, encoded_len);
        if (EVP_PKEY_fromdata_init(ctx) > 0
            && EVP_PKEY_fromdata(ctx, &pq_key, EVP_PKEY_PUBLIC_KEY, params)
                   > 0) {
            EVP_PKEY_CTX_free(ctx);
            return pq_key;
        }
        EVP_PKEY_CTX_free(ctx);
        ERR_clear_error();
    }
    return NULL;
}

int qkdkem_key_import_public(QKDKEM_KEY *key, const unsigned char *encoded,
                             size_t encoded_len)
{
    EVP_PKEY *pq_key;
    size_t pq_len;

    if (!key || !encoded || encoded_len <= QKD_KSID_SIZE)
        return 0;
    pq_len = encoded_len - QKD_KSID_SIZE;
    pq_key = import_inner_public(key, encoded, pq_len);
    if (!pq_key)
        return 0;

    EVP_PKEY_free(key->pq_key);
    key->pq_key = pq_key;
    key->has_private = 0;
    memcpy(key->qkd_id, encoded + pq_len, QKD_KSID_SIZE);
    qkdkem_qkd_session_free(key->qkd);
    key->qkd = NULL;
    key->has_qkd_key = 0;
    OPENSSL_cleanse(key->qkd_key, sizeof(key->qkd_key));
    return 1;
}

static int key_has(const void *keydata, int selection)
{
    const QKDKEM_KEY *key = keydata;

    if (!key || !key->pq_key)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) && !key->has_private)
        return 0;
    return 1;
}

static int key_validate(const void *keydata, int selection, int checktype)
{
    (void)checktype;
    return key_has(keydata, selection);
}

static int key_match(const void *keydata1, const void *keydata2, int selection)
{
    const QKDKEM_KEY *first = keydata1;
    const QKDKEM_KEY *second = keydata2;
    unsigned char *first_public = NULL;
    unsigned char *second_public = NULL;
    size_t first_len = 0;
    size_t second_len = 0;
    int matches = 0;

    if (!first || !second || first->algorithm != second->algorithm)
        return 0;
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 1;
    if (!qkdkem_key_public_bytes(first, &first_public, &first_len)
        || !qkdkem_key_public_bytes(second, &second_public, &second_len))
        goto done;
    matches = first_len == second_len
              && CRYPTO_memcmp(first_public, second_public, first_len) == 0;

done:
    OPENSSL_free(first_public);
    OPENSSL_free(second_public);
    return matches;
}

static int key_get_params(void *keydata, OSSL_PARAM params[])
{
    QKDKEM_KEY *key = keydata;
    OSSL_PARAM *param;
    unsigned char *encoded = NULL;
    size_t encoded_len = 0;
    int max_size;
    int bits;

    if (!key || !key->pq_key)
        return 0;
    bits = (int)key->algorithm->security_bits;
    max_size = EVP_PKEY_get_size(key->pq_key);
    if (max_size < 0 || max_size > INT_MAX - QKD_KSID_SIZE)
        return 0;
    max_size += QKD_KSID_SIZE;

    param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (param && !OSSL_PARAM_set_int(param, bits))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (param && !OSSL_PARAM_set_int(param, bits))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (param && !OSSL_PARAM_set_int(param, max_size))
        return 0;

    if (!OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)
        && !OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY))
        return 1;
    if (!qkdkem_key_public_bytes(key, &encoded, &encoded_len))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (param && !OSSL_PARAM_set_octet_string(param, encoded, encoded_len))
        goto error;
    param = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (param && !OSSL_PARAM_set_octet_string(param, encoded, encoded_len))
        goto error;
    OPENSSL_free(encoded);
    return 1;

error:
    OPENSSL_free(encoded);
    return 0;
}

static const OSSL_PARAM key_gettable_params[]
    = {OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
       OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
       OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
       OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
       OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
       OSSL_PARAM_END};

static const OSSL_PARAM *key_gettable(void *provctx)
{
    (void)provctx;
    return key_gettable_params;
}

static int key_set_params(void *keydata, const OSSL_PARAM params[])
{
    QKDKEM_KEY *key = keydata;
    const OSSL_PARAM *param;
    const void *encoded = NULL;
    size_t encoded_len = 0;

    if (!key)
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (!param)
        return 1;
    if (!OSSL_PARAM_get_octet_string_ptr(param, &encoded, &encoded_len))
        return 0;
    return qkdkem_key_import_public(key, encoded, encoded_len);
}

static const OSSL_PARAM key_settable_params[]
    = {OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
       OSSL_PARAM_END};

static const OSSL_PARAM *key_settable(void *provctx)
{
    (void)provctx;
    return key_settable_params;
}

static const OSSL_PARAM key_import_export_types[]
    = {OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
       OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
       OSSL_PARAM_END};

static const OSSL_PARAM *key_imexport_types(int selection)
{
    return selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY ? key_import_export_types
                                                      : NULL;
}

static int key_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param;
    const void *encoded = NULL;
    size_t encoded_len = 0;

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (!param)
        param = OSSL_PARAM_locate_const(params,
                                        OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (!param
        || !OSSL_PARAM_get_octet_string_ptr(param, &encoded, &encoded_len))
        return 0;
    return qkdkem_key_import_public(keydata, encoded, encoded_len);
}

static int key_export(void *keydata, int selection, OSSL_CALLBACK *callback,
                      void *arg)
{
    QKDKEM_KEY *key = keydata;
    unsigned char *encoded = NULL;
    size_t encoded_len = 0;
    OSSL_PARAM params[2];
    int result;

    if (!(selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
        || !qkdkem_key_public_bytes(key, &encoded, &encoded_len))
        return 0;
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  encoded, encoded_len);
    params[1] = OSSL_PARAM_construct_end();
    result = callback(params, arg);
    OPENSSL_free(encoded);
    return result;
}

static QKDKEM_GEN_CTX *gen_init(QKDKEM_PROV_CTX *provctx,
                                const QKDKEM_ALGORITHM *algorithm,
                                int selection)
{
    QKDKEM_GEN_CTX *genctx;

    genctx = OPENSSL_zalloc(sizeof(*genctx));
    if (!genctx)
        return NULL;
    genctx->provctx = provctx;
    genctx->algorithm = algorithm;
    genctx->selection = selection;
    return genctx;
}

static void *gen_key(void *vgenctx, OSSL_CALLBACK *callback, void *arg)
{
    QKDKEM_GEN_CTX *genctx = vgenctx;
    QKDKEM_KEY *key = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    (void)callback;
    (void)arg;
    if (!genctx)
        return NULL;
    key = qkdkem_key_new(genctx->provctx, genctx->algorithm);
    ctx = qkdkem_inner_ctx(genctx->provctx, genctx->algorithm);
    if (!key || !ctx || EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_generate(ctx, &key->pq_key) <= 0)
        goto error;
    key->has_private = 1;

#ifdef QKD_KEY_ID_CH
    if (!qkdkem_key_qkd(key, true)
        || !qkdkem_qkd_offer_start(key->qkd, key->qkd_id))
        goto error;
#    ifndef ETSI_004_API
    if (!qkdkem_qkd_offer_finish(key->qkd, key->qkd_key))
        goto error;
    key->has_qkd_key = 1;
#    endif
#endif

    EVP_PKEY_CTX_free(ctx);
    return key;

error:
    EVP_PKEY_CTX_free(ctx);
    qkdkem_key_free(key);
    return NULL;
}

static void gen_cleanup(void *genctx)
{
    OPENSSL_free(genctx);
}

static int gen_set_params(void *vgenctx, const OSSL_PARAM params[])
{
    QKDKEM_GEN_CTX *genctx = vgenctx;
    const OSSL_PARAM *param;
    const char *group = NULL;

    if (!genctx)
        return 0;
    param = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_GROUP_NAME);
    if (!param)
        return 1;
    if (!OSSL_PARAM_get_utf8_string_ptr(param, &group) || !group)
        return 0;
    return strcmp(group, genctx->algorithm->name) == 0;
}

static const OSSL_PARAM gen_settable_params[]
    = {OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, NULL, 0),
       OSSL_PARAM_END};

static const OSSL_PARAM *gen_settable(void *genctx, void *provctx)
{
    (void)genctx;
    (void)provctx;
    return gen_settable_params;
}

#define DEFINE_KEYMGMT(token, public_name, id, bits, inner1, inner2, inner3,   \
                       suffix)                                                 \
    static void *token##_new(void *provctx)                                    \
    {                                                                          \
        return qkdkem_key_new(provctx,                                         \
                              &qkdkem_algorithms[QKDKEM_INDEX_##token]);       \
    }                                                                          \
    static void *token##_gen_init(void *provctx, int selection,                \
                                  const OSSL_PARAM params[])                   \
    {                                                                          \
        (void)params;                                                          \
        return gen_init(provctx, &qkdkem_algorithms[QKDKEM_INDEX_##token],     \
                        selection);                                            \
    }                                                                          \
    const OSSL_DISPATCH qkdkem_##token##_keymgmt_functions[] = {               \
        {OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))token##_new},                  \
        {OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))qkdkem_key_free},             \
        {OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))key_has},                      \
        {OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))key_validate},            \
        {OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))key_match},                  \
        {OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))key_get_params},        \
        {OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))key_gettable},     \
        {OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*)(void))key_set_params},        \
        {OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*)(void))key_settable},     \
        {OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))key_import},                \
        {OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))key_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))key_export},                \
        {OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))key_imexport_types},  \
        {OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))token##_gen_init},        \
        {OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))gen_set_params},    \
        {OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))gen_settable}, \
        {OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))gen_key},                      \
        {OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))gen_cleanup},          \
        {0, NULL}};

enum {
#define DEFINE_INDEX(token, name, id, bits, inner1, inner2, inner3, suffix) \
    QKDKEM_INDEX_##token,
    QKDKEM_ALGORITHM_LIST(DEFINE_INDEX)
#undef DEFINE_INDEX
};

QKDKEM_ALGORITHM_LIST(DEFINE_KEYMGMT)

#undef DEFINE_KEYMGMT
