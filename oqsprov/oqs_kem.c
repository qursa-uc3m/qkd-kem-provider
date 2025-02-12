// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL rsa kem.
 *
 * ToDo: Adding hybrid alg support; More testing with more key types.
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <string.h>

#include "oqs_prov.h"

#ifdef NDEBUG
#define OQS_KEM_PRINTF(a)
#define OQS_KEM_PRINTF2(a, b)
#define OQS_KEM_PRINTF3(a, b, c)
#else
#define OQS_KEM_PRINTF(a)                                                      \
    if (getenv("OQSKEM"))                                                      \
    printf(a)
#define OQS_KEM_PRINTF2(a, b)                                                  \
    if (getenv("OQSKEM"))                                                      \
    printf(a, b)
#define OQS_KEM_PRINTF3(a, b, c)                                               \
    if (getenv("OQSKEM"))                                                      \
    printf(a, b, c)
#endif // NDEBUG

#define DEBUG_QKD

#ifdef NDEBUG
#define QKD_DEBUG(fmt, ...)
#else
#ifdef DEBUG_QKD
#define QKD_DEBUG(fmt, ...)                                                    \
    fprintf(stderr, "QKD DEBUG: %s:%d: " fmt "\n", __func__, __LINE__,         \
            ##__VA_ARGS__)
#else
#define QKD_DEBUG(fmt, ...)
#endif
#endif

static OSSL_FUNC_kem_encapsulate_init_fn oqs_kem_encaps_init;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 */
typedef struct {
    OSSL_LIB_CTX *libctx;
    OQSX_KEY *kem;
} PROV_OQSKEM_CTX;

/// Common KEM functions
static int oqs_kem_decapsencaps_init(void *vpkemctx, void *vkem,
                                     int operation) {
    PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;

    OQS_KEM_PRINTF3("OQS KEM provider called: _init : New: %p; old: %p \n",
                    vkem, pkemctx->kem);
    if (pkemctx == NULL || vkem == NULL || !oqsx_key_up_ref(vkem))
        return 0;
    oqsx_key_free(pkemctx->kem);
    pkemctx->kem = vkem;

    return 1;
}

static int oqs_kem_encaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[]) {
    OQS_KEM_PRINTF("OQS KEM provider called: encaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_ENCAPSULATE);
}

static int oqs_kem_decaps_init(void *vpkemctx, void *vkem,
                               const OSSL_PARAM params[]) {
    OQS_KEM_PRINTF("OQS KEM provider called: decaps_init\n");
    return oqs_kem_decapsencaps_init(vpkemctx, vkem, EVP_PKEY_OP_DECAPSULATE);
}

/// Quantum-Safe KEM functions (OQS)

static int oqs_qs_kem_encaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, unsigned char *secret,
                                     size_t *secretlen, int keyslot) {
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQS_KEM *kem_ctx = NULL;

    QKD_DEBUG("ENCAPS PQ keyslot: %d\n", keyslot);

    OQS_KEM_PRINTF("OQS KEM provider called: encaps\n");
    if (pkemctx->kem == NULL) {
        QKD_DEBUG("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }

    kem_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    if (pkemctx->kem->comp_pubkey == NULL ||
        pkemctx->kem->comp_pubkey[keyslot] == NULL) {
        QKD_DEBUG("OQS Warning: public key is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        QKD_DEBUG("OQS Warning: outlen is NULL\n");
        return -1;
    }
    if (secretlen == NULL) {
        QKD_DEBUG("OQS Warning: secretlen is NULL\n");
        return -1;
    }
    if (out == NULL || secret == NULL) {
        *outlen = kem_ctx->length_ciphertext;
        *secretlen = kem_ctx->length_shared_secret;
        QKD_DEBUG("KEM returning lengths %ld and %ld\n",
                  kem_ctx->length_ciphertext, kem_ctx->length_shared_secret);
        return 1;
    }

    if (*outlen < kem_ctx->length_ciphertext) {
        QKD_DEBUG("OQS Warning: out buffer too small\n");
        return -1;
    }
    if (*secretlen < kem_ctx->length_shared_secret) {
        QKD_DEBUG("OQS Warning: secret buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_ciphertext;
    *secretlen = kem_ctx->length_shared_secret;

    return OQS_SUCCESS == OQS_KEM_encaps(kem_ctx, out, secret,
                                         pkemctx->kem->comp_pubkey[keyslot]);
}

static int oqs_qs_kem_decaps_keyslot(void *vpkemctx, unsigned char *out,
                                     size_t *outlen, const unsigned char *in,
                                     size_t inlen, int keyslot) {
    const PROV_OQSKEM_CTX *pkemctx = (PROV_OQSKEM_CTX *)vpkemctx;
    const OQS_KEM *kem_ctx = NULL;

    QKD_DEBUG("DECAPS PQ keyslot: %d\n", keyslot);

    QKD_DEBUG("OQS KEM provider called: decaps\n");
    if (pkemctx->kem == NULL) {
        QKD_DEBUG("OQS Warning: OQS_KEM not initialized\n");
        return -1;
    }
    kem_ctx = pkemctx->kem->oqsx_provider_ctx.oqsx_qs_ctx.kem;
    if (pkemctx->kem->comp_privkey == NULL ||
        pkemctx->kem->comp_privkey[keyslot] == NULL) {
        QKD_DEBUG("OQS Warning: private key is NULL\n");
        return -1;
    }
    if (out == NULL) {
        if (outlen != NULL) {
            *outlen = kem_ctx->length_shared_secret;
        }
        QKD_DEBUG("KEM returning length %ld\n", kem_ctx->length_shared_secret);
        return 1;
    }
    if (inlen != kem_ctx->length_ciphertext) {
        QKD_DEBUG("OQS Warning: wrong input length\n");
        return 0;
    }
    if (in == NULL) {
        QKD_DEBUG("OQS Warning: in is NULL\n");
        return -1;
    }
    if (outlen == NULL) {
        QKD_DEBUG("OQS Warning: outlen is NULL\n");
        return -1;
    }
    if (*outlen < kem_ctx->length_shared_secret) {
        QKD_DEBUG("OQS Warning: out buffer too small\n");
        return -1;
    }
    *outlen = kem_ctx->length_shared_secret;

    if (pkemctx->kem->comp_privkey[keyslot] == NULL) {
        QKD_DEBUG("OQS Warning: comp_privkey[%d] is NULL\n", keyslot);
        return -1;
    }

    if (kem_ctx == NULL) {
        QKD_DEBUG("OQS Warning: kem_ctx is NULL\n");
        return -1;
    }

    return OQS_SUCCESS == OQS_KEM_decaps(kem_ctx, out, in,
                                         pkemctx->kem->comp_privkey[keyslot]);
}

#include "oqs_qkd_kem.c"

#define MAKE_QKD_KEM_FUNCTIONS(alg)                                            \
    const OSSL_DISPATCH oqs_##alg##_kem_functions[] = {                        \
        {OSSL_FUNC_KEM_NEWCTX, (void (*)(void))oqs_qkd_kem_newctx},            \
        {OSSL_FUNC_KEM_ENCAPSULATE_INIT, (void (*)(void))oqs_kem_encaps_init}, \
        {OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))oqs_qkd_kem_encaps},       \
        {OSSL_FUNC_KEM_DECAPSULATE_INIT, (void (*)(void))oqs_kem_decaps_init}, \
        {OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))oqs_qkd_kem_decaps},       \
        {OSSL_FUNC_KEM_FREECTX, (void (*)(void))oqs_qkd_kem_freectx},          \
        {0, NULL}};

// keep this just in case we need to become ALG-specific at some point in time
MAKE_QKD_KEM_FUNCTIONS(qkd)
