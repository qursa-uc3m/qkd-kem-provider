// SPDX-License-Identifier: Apache-2.0 AND MIT

#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include <string.h>

#include "test_common.h"
#include "tlstest_helpers.h"

static OSSL_LIB_CTX *libctx = NULL;
static char *modulename = NULL;
static char *configfile = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *certsdir = NULL;

char *test_mk_file_path(const char *dir, const char *file) {
#ifndef OPENSSL_SYS_VMS
    const char *sep = "/";
#else
    const char *sep = "";
#endif
    size_t len = strlen(dir) + strlen(sep) + strlen(file) + 1;
    char *full_file = OPENSSL_zalloc(len);

    if (full_file != NULL) {
        OPENSSL_strlcpy(full_file, dir, len);
        OPENSSL_strlcat(full_file, sep, len);
        OPENSSL_strlcat(full_file, file, len);
    }

    return full_file;
}

static int test_oqs_groups(const char *group_name) {
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int ret = 1, testresult = 0;

    if (!alg_is_enabled(group_name)) {
        printf("Not testing disabled algorithm %s.\n", group_name);
        return 1;
    }
    testresult = create_tls1_3_ctx_pair(libctx, &sctx, &cctx, cert, privkey);
    if (!testresult) {
        ret = -1;
        goto err;
    }

    testresult = create_tls_objects(sctx, cctx, &serverssl, &clientssl);

    if (!testresult) {
        ret = -2;
        goto err;
    }

    testresult = SSL_set1_groups_list(serverssl, group_name);
    if (!testresult) {
        ret = -3;
        goto err;
    }

    testresult = SSL_set1_groups_list(clientssl, group_name);
    if (!testresult) {
        ret = -4;
        goto err;
    }

    testresult = create_tls_connection(serverssl, clientssl, SSL_ERROR_NONE);
    if (!testresult) {
        ret = -5;
        goto err;
    }

err:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return ret;
}

static int test_group(const OSSL_PARAM params[], void *data) {
    int ret = 1;
    int *errcnt = (int *)data;
    const OSSL_PARAM *p =
        OSSL_PARAM_locate_const(params, OSSL_CAPABILITY_TLS_GROUP_NAME);

    // Add debug prints for parameter inspection
    fprintf(stderr, "Checking group parameters:\n");
    const OSSL_PARAM *curr = params;
    while (curr && curr->key) {
        fprintf(stderr, "  Parameter: %s, type: %d\n", curr->key,
                curr->data_type);
        if (curr->data_type == OSSL_PARAM_UTF8_STRING) {
            fprintf(stderr, "    Value: %s\n", (const char *)curr->data);
        } else if (curr->data_type == OSSL_PARAM_UNSIGNED_INTEGER) {
            unsigned int val;
            if (OSSL_PARAM_get_uint32(curr, &val) == 1) {
                fprintf(stderr, "    Value: %u\n", val);
            } else {
                fprintf(stderr, "    Error getting uint value\n");
            }
        }
        curr++;
    }

    if (p == NULL || p->data_type != OSSL_PARAM_UTF8_STRING) {
        fprintf(stderr, "Group name parameter not found or wrong type\n");
        ret = -1;
        goto err;
    }

    char *group_name = OPENSSL_strdup(p->data);

    ret = test_oqs_groups(group_name);

    // Check if group name starts with "qkd_"
    const char *handshake_type =
        strncmp(group_name, "qkd_", 4) == 0 ? "TLS-QKD-KEM" : "TLS-KEM";

    if (ret >= 0) {
        fprintf(stderr, cGREEN "  %s handshake test succeeded: %s" cNORM "\n",
                handshake_type, group_name);
    } else {
        fprintf(stderr,
                cRED "  %s handshake test failed: %s, return code: %d" cNORM
                     "\n",
                handshake_type, group_name, ret);
        ERR_print_errors_fp(stderr);
        (*errcnt)++;
    }

err:
    OPENSSL_free(group_name);
    return ret;
}

static int test_provider_groups(OSSL_PROVIDER *provider, void *vctx) {
    const char *provname = OSSL_PROVIDER_get0_name(provider);

    if (!strcmp(provname, PROVIDER_NAME_OQS))
        return OSSL_PROVIDER_get_capabilities(provider, "TLS-GROUP", test_group,
                                              vctx);
    else
        return 1;
}

int main(int argc, char *argv[]) {
    size_t i;
    int errcnt = 0, test = 0;

    T((libctx = OSSL_LIB_CTX_new()) != NULL);
    T(argc == 4);
    modulename = argv[1];
    configfile = argv[2];
    certsdir = argv[3];

    T(cert = test_mk_file_path(certsdir, "servercert.pem"));
    T(privkey = test_mk_file_path(certsdir, "serverkey.pem"));

    load_oqs_provider(libctx, modulename, configfile);

    T(OSSL_PROVIDER_available(libctx, "default"));

    T(OSSL_PROVIDER_do_all(libctx, test_provider_groups, &errcnt));

    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OSSL_LIB_CTX_free(libctx);
    TEST_ASSERT(errcnt == 0)
    return !test;
}
