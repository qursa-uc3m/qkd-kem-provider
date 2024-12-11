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

#define ETSI_014_API // or ETSI_014_API

#include <openssl/evp.h>
#include <stdbool.h>
#include <stdint.h>
#include <qkd-etsi-api/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api/etsi014/api.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Main QKD context structure */
typedef struct {
    unsigned char key_id[QKD_KSID_SIZE];
    char *source_uri;
    char *dest_uri;
    EVP_PKEY *key;
    bool is_initiator;
    bool is_connected;
#ifdef ETSI_004_API // TODO_QKD: check if we should do something for the ETSI_014_API case
    struct qkd_qos_s qos;
    struct qkd_metadata_s metadata;
#endif
} QKD_CTX;

#ifdef ETSI_004_API
/* ETSI API Wrapper Functions - maintaining original function signatures */
bool qkd_open(QKD_CTX *ctx);
bool qkd_close(QKD_CTX *ctx);
bool qkd_get_key(QKD_CTX *ctx);
#endif /* ETSI_004_API */
#ifdef ETSI_014_API
bool qkd_get_status(QKD_CTX *ctx);
bool qkd_get_key(QKD_CTX *ctx);
bool qkd_get_key_with_ids(QKD_CTX *ctx);
#endif /* ETSI_014_API */

#ifdef __cplusplus
}
#endif

#endif /* QKD_ETSI_API_WRAPPER_H_ */