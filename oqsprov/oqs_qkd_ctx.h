/*
 * Copyright (C) 2024 Javier Blanco-Romero @fj-blanco (UC3M, QURSA project)
 */

/*
 * oqs_qkd_ctx.h
 * QKD context initialization
 */
#ifndef OQS_QKD_CTX_H
#define OQS_QKD_CTX_H

#include <stdbool.h>
#include <string.h>
#include "oqs_prov.h"

// QKD context initialization 
int oqs_init_qkd_context(OQSX_KEY *key, bool is_initiator);

#endif /* OQS_QKD_CTX_H */