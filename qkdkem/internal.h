/* SPDX-License-Identifier: MIT */
#ifndef QKDKEM_INTERNAL_H
#define QKDKEM_INTERNAL_H

#include "algorithms.h"
#include "qkd.h"

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/proverr.h>

#include <stdatomic.h>
#include <stddef.h>

#define QKDKEM_PROVIDER_NAME "qkdkemprovider"
#define QKDKEM_INNER_COUNT   3

typedef struct {
    const char *name;
    unsigned int group_id;
    unsigned int security_bits;
    const char *inner_names[QKDKEM_INNER_COUNT];
    const char *env_suffix;
} QKDKEM_ALGORITHM;

typedef struct {
    const OSSL_CORE_HANDLE *handle;
    OSSL_LIB_CTX *libctx;
} QKDKEM_PROV_CTX;

typedef struct qkdkem_key {
    QKDKEM_PROV_CTX *provctx;
    const QKDKEM_ALGORITHM *algorithm;
    EVP_PKEY *pq_key;
    QKDKEM_QKD_SESSION *qkd;
    unsigned char qkd_id[QKD_KSID_SIZE];
    unsigned char qkd_key[QKD_KEY_SIZE];
    int has_private;
    int has_qkd_key;
    _Atomic int references;
} QKDKEM_KEY;

extern const QKDKEM_ALGORITHM qkdkem_algorithms[];
extern const size_t qkdkem_algorithm_count;
extern const OSSL_DISPATCH qkdkem_kem_functions[];

EVP_PKEY_CTX *qkdkem_inner_ctx(QKDKEM_PROV_CTX *provctx,
                               const QKDKEM_ALGORITHM *algorithm);
int qkdkem_algorithm_available(QKDKEM_PROV_CTX *provctx,
                               const QKDKEM_ALGORITHM *algorithm);
unsigned int qkdkem_algorithm_group_id(const QKDKEM_ALGORITHM *algorithm);

QKDKEM_KEY *qkdkem_key_new(QKDKEM_PROV_CTX *provctx,
                           const QKDKEM_ALGORITHM *algorithm);
int qkdkem_key_up_ref(QKDKEM_KEY *key);
void qkdkem_key_free(void *keydata);
int qkdkem_key_public_bytes(const QKDKEM_KEY *key, unsigned char **out,
                            size_t *outlen);
int qkdkem_key_import_public(QKDKEM_KEY *key, const unsigned char *encoded,
                             size_t encoded_len);
QKDKEM_QKD_SESSION *qkdkem_key_qkd(QKDKEM_KEY *key, bool initiator);

#define QKDKEM_DECLARE_KEYMGMT(token, name, id, bits, inner1, inner2, inner3, \
                               suffix)                                        \
    extern const OSSL_DISPATCH qkdkem_##token##_keymgmt_functions[];
QKDKEM_ALGORITHM_LIST(QKDKEM_DECLARE_KEYMGMT)
#undef QKDKEM_DECLARE_KEYMGMT

#endif
