/* SPDX-License-Identifier: MIT */
#include "internal.h"

#include <openssl/ssl.h>

#include <string.h>
#ifdef _WIN32
#    define strcasecmp _stricmp
#else
#    include <strings.h>
#endif

#ifndef QKDKEM_VERSION
#    define QKDKEM_VERSION "dev"
#endif

static const OSSL_PARAM provider_params[]
    = {OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
       OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
       OSSL_PARAM_END};

static const OSSL_PARAM *provider_gettable_params(void *provctx)
{
    (void)provctx;
    return provider_params;
}

static int provider_get_params(void *provctx, OSSL_PARAM params[])
{
    OSSL_PARAM *param;

    (void)provctx;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (param
        && !OSSL_PARAM_set_utf8_ptr(param, "QKD provider-to-provider KEM"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (param && !OSSL_PARAM_set_utf8_ptr(param, QKDKEM_VERSION))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (param
        && !OSSL_PARAM_set_utf8_ptr(param,
                                    "EVP-delegating QKD/PQ hybrid provider"))
        return 0;
    param = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (param && !OSSL_PARAM_set_int(param, 1))
        return 0;
    return 1;
}

#define STRINGIFY_INNER(value) #value
#define STRINGIFY(value)       STRINGIFY_INNER(value)

#define QKDKEM_KEM_ENTRY(token, name, id, bits, inner1, inner2, inner3, \
                         suffix)                                        \
    {.algorithm_names = name,                                           \
     .property_definition                                               \
     = "provider=qkdkemprovider,qkdkem.security_bits=" STRINGIFY(bits), \
     .implementation = qkdkem_kem_functions},

static const OSSL_ALGORITHM kem_algorithms[]
    = {QKDKEM_ALGORITHM_LIST(QKDKEM_KEM_ENTRY){.algorithm_names = NULL}};

#undef QKDKEM_KEM_ENTRY

#define QKDKEM_KEYMGMT_ENTRY(token, name, id, bits, inner1, inner2, inner3, \
                             suffix)                                        \
    {.algorithm_names = name,                                               \
     .property_definition                                                   \
     = "provider=qkdkemprovider,qkdkem.security_bits=" STRINGIFY(bits),     \
     .implementation = qkdkem_##token##_keymgmt_functions},

static const OSSL_ALGORITHM keymgmt_algorithms[]
    = {QKDKEM_ALGORITHM_LIST(QKDKEM_KEYMGMT_ENTRY){.algorithm_names = NULL}};

#undef QKDKEM_KEYMGMT_ENTRY

static const OSSL_ALGORITHM *provider_query(void *provctx, int operation_id,
                                            int *no_cache)
{
    (void)provctx;
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEM:
        return kem_algorithms;
    case OSSL_OP_KEYMGMT:
        return keymgmt_algorithms;
    default:
        return NULL;
    }
}

static int provider_get_capabilities(void *vprovctx, const char *capability,
                                     OSSL_CALLBACK *callback, void *arg)
{
    QKDKEM_PROV_CTX *provctx = vprovctx;
    size_t i;

    if (strcasecmp(capability, "TLS-GROUP") != 0)
        return 0;

    for (i = 0; i < qkdkem_algorithm_count; i++) {
        const QKDKEM_ALGORITHM *algorithm = &qkdkem_algorithms[i];
        unsigned int group_id;
        unsigned int security_bits = algorithm->security_bits;
        int min_tls = TLS1_3_VERSION;
        int max_tls = 0;
        int min_dtls = -1;
        int max_dtls = -1;
        int is_kem = 1;
        OSSL_PARAM params[11];

        if (!qkdkem_algorithm_available(provctx, algorithm))
            continue;
        group_id = qkdkem_algorithm_group_id(algorithm);
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_NAME, (char *)algorithm->name, 0);
        params[1] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, (char *)algorithm->name,
            0);
        params[2] = OSSL_PARAM_construct_utf8_string(
            OSSL_CAPABILITY_TLS_GROUP_ALG, (char *)algorithm->name, 0);
        params[3] = OSSL_PARAM_construct_uint(OSSL_CAPABILITY_TLS_GROUP_ID,
                                              &group_id);
        params[4] = OSSL_PARAM_construct_uint(
            OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, &security_bits);
        params[5] = OSSL_PARAM_construct_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS,
                                             &min_tls);
        params[6] = OSSL_PARAM_construct_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS,
                                             &max_tls);
        params[7] = OSSL_PARAM_construct_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS,
                                             &min_dtls);
        params[8] = OSSL_PARAM_construct_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS,
                                             &max_dtls);
        params[9] = OSSL_PARAM_construct_int(OSSL_CAPABILITY_TLS_GROUP_IS_KEM,
                                             &is_kem);
        params[10] = OSSL_PARAM_construct_end();
        if (!callback(params, arg))
            return 0;
    }
    return 1;
}

static void provider_teardown(void *vprovctx)
{
    QKDKEM_PROV_CTX *provctx = vprovctx;

    if (!provctx)
        return;
    OSSL_LIB_CTX_free(provctx->libctx);
    OPENSSL_free(provctx);
}

static const OSSL_DISPATCH provider_dispatch[]
    = {{OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))provider_teardown},
       {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
        (void (*)(void))provider_gettable_params},
       {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))provider_get_params},
       {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))provider_query},
       {OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
        (void (*)(void))provider_get_capabilities},
       {0, NULL}};

#if defined(_WIN32)
__declspec(dllexport)
#else
__attribute__((visibility("default")))
#endif
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
                       const OSSL_DISPATCH *dispatch, const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    QKDKEM_PROV_CTX *provctx = OPENSSL_zalloc(sizeof(*provctx));

    if (!provctx)
        return 0;
    provctx->handle = handle;
    provctx->libctx = OSSL_LIB_CTX_new_child(handle, dispatch);
    if (!provctx->libctx) {
        OPENSSL_free(provctx);
        return 0;
    }
    *vprovctx = provctx;
    *out = provider_dispatch;
    return 1;
}
