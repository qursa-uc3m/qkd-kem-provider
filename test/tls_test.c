/* SPDX-License-Identifier: MIT */
#include "tlstest_helpers.h"

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

#include <stdio.h>

int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *qkd_provider = NULL;
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL *server = NULL;
    SSL *client = NULL;
    int ok = 0;

    if (argc != 3)
        return 2;
    libctx = OSSL_LIB_CTX_new();
    default_provider = OSSL_PROVIDER_load(libctx, "default");
    qkd_provider = OSSL_PROVIDER_load(libctx, "qkdkemprovider");
    if (!libctx || !default_provider || !qkd_provider)
        goto done;
    if (!create_tls1_3_ctx_pair(libctx, &server_ctx, &client_ctx, argv[1],
                                argv[2])
        || !create_tls_objects(server_ctx, client_ctx, &server, &client)
        || !SSL_set1_groups_list(server, "qkd_mlkem768")
        || !SSL_set1_groups_list(client, "qkd_mlkem768")
        || !create_tls_connection(server, client, SSL_ERROR_NONE))
        goto done;
    ok = 1;

done:
    if (!ok)
        ERR_print_errors_fp(stderr);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(server_ctx);
    SSL_CTX_free(client_ctx);
    OSSL_PROVIDER_unload(qkd_provider);
    OSSL_PROVIDER_unload(default_provider);
    OSSL_LIB_CTX_free(libctx);
    return ok ? 0 : 1;
}
