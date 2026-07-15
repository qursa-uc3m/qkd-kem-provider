/* SPDX-License-Identifier: MIT */
#include "internal.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QKDKEM_ALGORITHM_ENTRY(token, public_name, id, bits, inner1, inner2, \
                               inner3, suffix)                               \
    {public_name, id, bits, {inner1, inner2, inner3}, suffix},

const QKDKEM_ALGORITHM qkdkem_algorithms[]
    = {QKDKEM_ALGORITHM_LIST(QKDKEM_ALGORITHM_ENTRY)};

#undef QKDKEM_ALGORITHM_ENTRY

const size_t qkdkem_algorithm_count
    = sizeof(qkdkem_algorithms) / sizeof(qkdkem_algorithms[0]);

static const char *inner_properties(void)
{
    const char *properties = getenv("QKDKEM_INNER_PROPERTIES");

    return properties && *properties ? properties : "provider!=qkdkemprovider";
}

EVP_PKEY_CTX *qkdkem_inner_ctx(QKDKEM_PROV_CTX *provctx,
                               const QKDKEM_ALGORITHM *algorithm)
{
    EVP_PKEY_CTX *ctx;
    size_t i;

    if (!provctx || !algorithm)
        return NULL;

    for (i = 0; i < QKDKEM_INNER_COUNT && algorithm->inner_names[i]; i++) {
        ctx = EVP_PKEY_CTX_new_from_name(
            provctx->libctx, algorithm->inner_names[i], inner_properties());
        if (ctx)
            return ctx;
        ERR_clear_error();
    }
    return NULL;
}

int qkdkem_algorithm_available(QKDKEM_PROV_CTX *provctx,
                               const QKDKEM_ALGORITHM *algorithm)
{
    EVP_PKEY_CTX *ctx = qkdkem_inner_ctx(provctx, algorithm);

    EVP_PKEY_CTX_free(ctx);
    return ctx != NULL;
}

static unsigned int configured_group_id(const char *prefix, const char *suffix)
{
    char name[96];
    const char *value;
    char *end = NULL;
    unsigned long parsed;
    int length;

    length = snprintf(name, sizeof(name), "%s%s", prefix, suffix);
    if (length < 0 || (size_t)length >= sizeof(name))
        return 0;
    value = getenv(name);
    if (!value || !*value)
        return 0;

    errno = 0;
    parsed = strtoul(value, &end, 0);
    if (errno || !end || *end || parsed == 0 || parsed > 0xffffUL)
        return 0;
    return (unsigned int)parsed;
}

unsigned int qkdkem_algorithm_group_id(const QKDKEM_ALGORITHM *algorithm)
{
    unsigned int configured;

    configured
        = configured_group_id("QKDKEM_CODEPOINT_", algorithm->env_suffix);
    if (!configured)
        configured
            = configured_group_id("OQS_CODEPOINT_QKD_", algorithm->env_suffix);
    return configured ? configured : algorithm->group_id;
}
