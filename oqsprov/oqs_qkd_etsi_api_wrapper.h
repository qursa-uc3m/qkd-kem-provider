/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_etsi_api_wrapper.h
 * Wrapper for QKD ETSI API to maintain compatibility with existing QKD_CTX
 * interface
 */

#ifndef QKD_ETSI_API_WRAPPER_H_
#define QKD_ETSI_API_WRAPPER_H_

#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <qkd-etsi-api/api.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Main QKD context structure */
typedef struct {
    unsigned char key_id[QKD_KSID_SIZE];
    char *source_uri;
    char *dest_uri;
    EVP_PKEY *key;
    struct qkd_qos_s qos;
    bool is_initiator;
    bool is_connected;
    struct qkd_metadata_s metadata;
} QKD_CTX;

/* ETSI API Wrapper Functions - maintaining original function signatures */
bool qkd_open(QKD_CTX *ctx);
bool qkd_close(QKD_CTX *ctx);
bool qkd_get_key(QKD_CTX *ctx);

#ifdef __cplusplus
}
#endif

#endif /* QKD_ETSI_API_WRAPPER_H_ */