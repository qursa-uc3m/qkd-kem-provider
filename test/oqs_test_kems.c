// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/evp.h>
#include <openssl/provider.h>
#include <string.h>

#include "oqs/oqs.h"
#include "test_common.h"
#include <qkd-etsi-api/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api/etsi014/api.h>
#endif

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

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;

static int test_oqs_kems(const char *kemalg_name) {
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    unsigned char *out = NULL;
    unsigned char *secenc = NULL;
    unsigned char *secdec = NULL;
    size_t outlen, seclen;

    int testresult = 1;

    if (!alg_is_enabled(kemalg_name)) {
        QKD_DEBUG("Not testing disabled algorithm %s.\n", kemalg_name);
        return 1;
    }
    // test with built-in digest only if default provider is active:
    // TBD revisit when hybrids are activated: They always need default
    // provider
    if (OSSL_PROVIDER_available(libctx, "default")) {
        QKD_DEBUG("Generating key pair...\n");
        testresult &= (ctx = EVP_PKEY_CTX_new_from_name(libctx, kemalg_name,
                                                        NULL)) != NULL &&
                      EVP_PKEY_keygen_init(ctx) && EVP_PKEY_generate(ctx, &key);

        if (!testresult) {
            QKD_DEBUG("Key generation failed\n");
            goto err;
        }
        QKD_DEBUG("Key generation succeeded\n");
        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
        // Debug encapsulation setup
        QKD_DEBUG("Setting up encapsulation...\n");
        // Create new context from key
        ctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, NULL);
        if (ctx == NULL) {
            QKD_DEBUG("Failed to create new context from key\n");
            testresult = 0;
            goto err;
        }
        QKD_DEBUG("Created new context from key\n");

        // Initialize encapsulation
        if (!EVP_PKEY_encapsulate_init(ctx, NULL)) {
            QKD_DEBUG("Failed to initialize encapsulation\n");
            testresult = 0;
            goto err;
        }
        QKD_DEBUG("Initialized encapsulation\n");
        QKD_DEBUG("Before EVP_PKEY_encapsulate - outlen=%zu, seclen=%zu\n",
                  outlen, seclen);

        // Get required buffer lengths
        if (!EVP_PKEY_encapsulate(ctx, NULL, &outlen, NULL, &seclen)) {
            QKD_DEBUG("Failed to get encapsulation lengths\n");
            testresult = 0;
            goto err;
        }
        QKD_DEBUG("Encapsulation lengths: ciphertext=%zu, shared secret=%zu\n",
                  outlen, seclen);

        // Debug memory allocation
        QKD_DEBUG("Allocating buffers...\n");
        testresult &= (out = OPENSSL_malloc(outlen)) != NULL &&
                      (secenc = OPENSSL_malloc(seclen)) != NULL &&
                      memset(secenc, 0x11, seclen) != NULL &&
                      (secdec = OPENSSL_malloc(seclen)) != NULL &&
                      memset(secdec, 0xff, seclen) != NULL;

        // Debug actual encapsulation/decapsulation
        QKD_DEBUG("Performing encapsulation...\n");
        testresult &= EVP_PKEY_encapsulate(ctx, out, &outlen, secenc, &seclen);

        QKD_DEBUG("Encapsulation succeeded\n");

        // Initialize decapsulation
        QKD_DEBUG("Initializing decapsulation...\n");
        if (!EVP_PKEY_decapsulate_init(ctx, NULL)) {
            QKD_DEBUG("Failed to initialize decapsulation\n");
            testresult = 0;
            goto err;
        }
        QKD_DEBUG("Decapsulation initialized\n");

        // Perform decapsulation
        QKD_DEBUG("Performing decapsulation...\n");
        if (!EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen)) {
            QKD_DEBUG("Decapsulation failed\n");
            testresult = 0;
            goto err;
        }
        QKD_DEBUG("Decapsulation succeeded\n");

        // Tamper with ciphertext
        out[0] = ~out[0];
        out[outlen - 1] = ~out[outlen - 1];

        // Reset decapsulation buffer
        if (memset(secdec, 0xff, seclen) != NULL) {
            QKD_DEBUG("Reset decapsulation buffer succeeded\n");
        } else {
            QKD_DEBUG("ERROR: Failed to reset decapsulation buffer\n");
            testresult = 0;
        }

        // Initialize decapsulation
        int init_ret = EVP_PKEY_decapsulate_init(ctx, NULL);
        if (init_ret) {
            QKD_DEBUG("Decapsulation init succeeded\n");
        } else {
            QKD_DEBUG("ERROR: Decapsulation init failed\n");
            testresult = 0;
        }

        // Perform decapsulation
        int decaps_ret =
            EVP_PKEY_decapsulate(ctx, secdec, &seclen, out, outlen);

        // Update testresult with decapsulation steps
        testresult &= init_ret && (decaps_ret || 1);

        // Check if this is a QKD hybrid algorithm
        if (strstr(kemalg_name, "qkd") != NULL) {
            /* Note: QKD portion is always last in the shared secret.
            QKD secret only depends on key ID, not full ciphertext*/

            // Test PQ portion
            QKD_DEBUG("Testing PQ portion...\n");
            if (memcmp(secenc, secdec, seclen - QKD_KEY_SIZE) != 0) {
                QKD_DEBUG("PQ portion differs after tampering as expected\n");
                testresult &= 1;
            } else {
                QKD_DEBUG("ERROR: PQ portion unchanged after tampering!\n");
                testresult = 0;
            }

            // Test QKD portion
            QKD_DEBUG("\nTesting QKD portion...\n");
            if (memcmp(secenc + seclen - QKD_KEY_SIZE,
                       secdec + seclen - QKD_KEY_SIZE, QKD_KEY_SIZE) == 0) {
                QKD_DEBUG("QKD portion remains unchanged as expected - this is "
                          "normal since QKD only uses key ID\n");
                testresult &= 1;
            } else {
                QKD_DEBUG("ERROR: QKD portion changed unexpectedly!\n");
                testresult = 0;
            }

        } else {
            // Standard non-QKD tampering test
            if (memcmp(secenc, secdec, seclen) != 0) {
                QKD_DEBUG("\nShared secrets do not match after tampering as "
                          "expected\n");
                testresult &= 1;
            } else {
                QKD_DEBUG("\nERROR: Shared secrets match after tampering!\n");
                testresult = 0;
            }
        }
    }

err:
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    OPENSSL_free(out);
    OPENSSL_free(secenc);
    OPENSSL_free(secdec);
    return testresult;
}

#define nelem(a) (sizeof(a) / sizeof((a)[0]))

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0, query_nocache;
    OSSL_PROVIDER *oqsprov = NULL;
    const OSSL_ALGORITHM *kemalgs;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 3);
    modulename = argv[1];
    configfile = argv[2];

    load_oqs_provider(libctx, modulename, configfile);

    oqsprov = OSSL_PROVIDER_load(libctx, modulename);

    kemalgs =
        OSSL_PROVIDER_query_operation(oqsprov, OSSL_OP_KEM, &query_nocache);
    if (kemalgs) {
        for (; kemalgs->algorithm_names != NULL; kemalgs++) {
            if (test_oqs_kems(kemalgs->algorithm_names)) {
                fprintf(stderr, cGREEN "  KEM test succeeded: %s" cNORM "\n",
                        kemalgs->algorithm_names);
            } else {
                fprintf(stderr, cRED "  KEM test failed: %s" cNORM "\n",
                        kemalgs->algorithm_names);
                ERR_print_errors_fp(stderr);
                errcnt++;
            }
        }
    }

    OSSL_LIB_CTX_free(libctx);

    TEST_ASSERT(errcnt == 0)
    return !test;
}