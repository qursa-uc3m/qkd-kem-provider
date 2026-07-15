/* SPDX-License-Identifier: MIT */
#ifndef QKDKEM_QKD_H
#define QKDKEM_QKD_H

#include <stdbool.h>
#include <stddef.h>

#ifdef QKDKEM_QKD_FLAT_HEADERS
#    include <qkd_etsi_api.h>
#else
#    include <qkd-etsi-api-c-wrapper/qkd_etsi_api.h>
#endif

typedef struct qkdkem_qkd_session QKDKEM_QKD_SESSION;

QKDKEM_QKD_SESSION *qkdkem_qkd_session_new(bool initiator);
void qkdkem_qkd_session_free(QKDKEM_QKD_SESSION *session);

int qkdkem_qkd_offer_start(QKDKEM_QKD_SESSION *session,
                           unsigned char id[QKD_KSID_SIZE]);
int qkdkem_qkd_offer_accept(QKDKEM_QKD_SESSION *session,
                            const unsigned char id[QKD_KSID_SIZE],
                            unsigned char key[QKD_KEY_SIZE]);
int qkdkem_qkd_offer_finish(QKDKEM_QKD_SESSION *session,
                            unsigned char key[QKD_KEY_SIZE]);

int qkdkem_qkd_response_create(QKDKEM_QKD_SESSION *session,
                               unsigned char id[QKD_KSID_SIZE],
                               unsigned char key[QKD_KEY_SIZE]);
int qkdkem_qkd_response_accept(QKDKEM_QKD_SESSION *session,
                               const unsigned char id[QKD_KSID_SIZE],
                               unsigned char key[QKD_KEY_SIZE]);

#endif
