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

//#define ETSI_014_API // or ETSI_014_API
#define ETSI_004_API // or ETSI_014_API

#include <openssl/evp.h>
#include <qkd-etsi-api/qkd_config.h>
#include <qkd-etsi-api/qkd_etsi_api.h>
#include <stdbool.h>
#include <stdint.h>
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
    unsigned char key_id[37]; // 36 chars for UUID + null terminator
    char *source_uri;         // URI for source KME
    char *dest_uri;           // URI for destination KME
    char *master_kme;         // Master KME hostname from env
    char *slave_kme;          // Slave KME hostname from env
    char *master_sae;         // Master SAE ID
    char *slave_sae;          // Slave SAE ID
    char *sae_id;             // SAE ID for this context
    EVP_PKEY *key;
    bool is_initiator;
#ifdef ETSI_004_API
    bool is_connected;
    struct qkd_qos_s qos;
    struct qkd_metadata_s metadata;
#elif defined(ETSI_014_API)
    qkd_status_t status;
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