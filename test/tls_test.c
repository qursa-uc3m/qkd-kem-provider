/* SPDX-License-Identifier: MIT */
#include "tlstest_helpers.h"

#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>

#include <stdio.h>
#include <string.h>

static int client_hellos;

static void count_client_hellos(int write_p, int version, int content_type,
                                const void *buf, size_t len, SSL *ssl,
                                void *arg)
{
    (void)version;
    (void)ssl;
    (void)arg;
    if (write_p && content_type == SSL3_RT_HANDSHAKE && len > 0
        && *(const unsigned char *)buf == SSL3_MT_CLIENT_HELLO)
        client_hellos++;
}

/*
 * Usage: tls_test <cert> <key> [hrr]
 *
 * With "hrr" the client's first key share is X25519, which the server does
 * not accept, so the qkd group is only reached through a HelloRetryRequest.
 */
int main(int argc, char **argv)
{
    OSSL_LIB_CTX *libctx = NULL;
    OSSL_PROVIDER *default_provider = NULL;
    OSSL_PROVIDER *qkd_provider = NULL;
    SSL_CTX *server_ctx = NULL;
    SSL_CTX *client_ctx = NULL;
    SSL *server = NULL;
    SSL *client = NULL;
    int hrr = argc == 4 && strcmp(argv[3], "hrr") == 0;
    int ok = 0;

    if (argc != 3 && !hrr)
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
        || !SSL_set1_groups_list(client,
                                 hrr ? "X25519:qkd_mlkem768" : "qkd_mlkem768"))
        goto done;
    SSL_set_msg_callback(client, count_client_hellos);
    if (!create_tls_connection(server, client, SSL_ERROR_NONE))
        goto done;
    ok = client_hellos == (hrr ? 2 : 1)
         && strcmp(SSL_group_to_name(client, SSL_get_negotiated_group(client)),
                   "qkd_mlkem768")
                == 0;
    if (!ok)
        fprintf(stderr, "unexpected handshake: %d ClientHello(s)\n",
                client_hellos);

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
