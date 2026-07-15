/* SPDX-License-Identifier: MIT */
#include "qkd.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef QKDKEM_QKD_FLAT_HEADERS
#    ifdef ETSI_004_API
#        include <etsi004/api.h>
#    else
#        include <etsi014/api.h>
#    endif
#else
#    ifdef ETSI_004_API
#        include <qkd-etsi-api-c-wrapper/etsi004/api.h>
#    else
#        include <qkd-etsi-api-c-wrapper/etsi014/api.h>
#    endif
#endif

#ifndef QKD_METADATA_MAX_SIZE
#    define QKD_METADATA_MAX_SIZE 1024U
#endif

struct qkdkem_qkd_session {
    bool initiator;
    unsigned char id[QKD_KSID_SIZE];
    unsigned char key[QKD_KEY_SIZE];
    bool has_key;
#ifdef ETSI_004_API
    char *source_uri;
    char *destination_uri;
    bool connected;
    struct qkd_qos_s qos;
    struct qkd_metadata_s metadata;
#else
    char *master_kme;
    char *slave_kme;
    char *master_sae;
    char *slave_sae;
#endif
};

static char *copy_environment(const char *name)
{
    const char *value = getenv(name);

    return value && *value ? OPENSSL_strdup(value) : NULL;
}

#ifdef ETSI_004_API
static uint32_t environment_u32(const char *name, uint32_t fallback)
{
    const char *value = getenv(name);
    char *end = NULL;
    unsigned long parsed;

    if (!value || !*value)
        return fallback;
    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno || !end || *end || parsed > UINT32_MAX)
        return fallback;
    return (uint32_t)parsed;
}

static int qkd_open_session(QKDKEM_QKD_SESSION *session)
{
    uint32_t status = 0;
    uint32_t result;

    if (!session || session->connected)
        return session != NULL;
    result = OPEN_CONNECT(session->source_uri, session->destination_uri,
                          &session->qos, session->id, &status);
    if (result != status
        || (status != QKD_STATUS_SUCCESS
            && status != QKD_STATUS_PEER_NOT_CONNECTED))
        return 0;
    session->connected = true;
    return 1;
}

static int qkd_read_session_key(QKDKEM_QKD_SESSION *session)
{
    uint32_t status = 0;
    uint32_t index = 0;
    uint32_t result;

    result = GET_KEY(session->id, &index, session->key, &session->metadata,
                     &status);
    if (result != status || status != QKD_STATUS_SUCCESS) {
        OPENSSL_cleanse(session->key, sizeof(session->key));
        return 0;
    }
    session->has_key = true;
    return 1;
}
#else
static int hex_value(char value)
{
    if (value >= '0' && value <= '9')
        return value - '0';
    if (value >= 'a' && value <= 'f')
        return value - 'a' + 10;
    if (value >= 'A' && value <= 'F')
        return value - 'A' + 10;
    return -1;
}

static int uuid_parse_binary(const char *text,
                             unsigned char binary[QKD_KSID_SIZE])
{
    static const size_t hyphens[] = {8, 13, 18, 23};
    size_t text_index = 0;
    size_t binary_index = 0;
    size_t hyphen_index = 0;

    if (!text || strlen(text) != 36)
        return 0;
    while (text_index < 36) {
        int high;
        int low;

        if (hyphen_index < sizeof(hyphens) / sizeof(hyphens[0])
            && text_index == hyphens[hyphen_index]) {
            if (text[text_index++] != '-')
                return 0;
            hyphen_index++;
            continue;
        }
        if (text_index + 1 >= 36 || binary_index >= QKD_KSID_SIZE)
            return 0;
        high = hex_value(text[text_index++]);
        low = hex_value(text[text_index++]);
        if (high < 0 || low < 0)
            return 0;
        binary[binary_index++] = (unsigned char)((high << 4) | low);
    }
    return binary_index == QKD_KSID_SIZE;
}

static void uuid_format(const unsigned char binary[QKD_KSID_SIZE],
                        char text[37])
{
    static const char hex[] = "0123456789abcdef";
    size_t binary_index;
    size_t text_index = 0;

    for (binary_index = 0; binary_index < QKD_KSID_SIZE; binary_index++) {
        if (binary_index == 4 || binary_index == 6 || binary_index == 8
            || binary_index == 10)
            text[text_index++] = '-';
        text[text_index++] = hex[binary[binary_index] >> 4];
        text[text_index++] = hex[binary[binary_index] & 0x0f];
    }
    text[text_index] = '\0';
}

static int base64_decode_key(const char *encoded,
                             unsigned char key[QKD_KEY_SIZE])
{
    static const size_t encoded_key_size = 44;
    size_t encoded_len;
    unsigned char decoded[QKD_KEY_SIZE + 1];
    int decoded_len;

    if (!encoded)
        return 0;
    encoded_len = strlen(encoded);
    if (encoded_len != encoded_key_size || encoded[encoded_len - 1] != '='
        || encoded[encoded_len - 2] == '=')
        return 0;

    decoded_len = EVP_DecodeBlock(decoded, (const unsigned char *)encoded,
                                  (int)encoded_len);
    if (decoded_len != (int)sizeof(decoded)) {
        OPENSSL_cleanse(decoded, sizeof(decoded));
        return 0;
    }
    memcpy(key, decoded, QKD_KEY_SIZE);
    OPENSSL_cleanse(decoded, sizeof(decoded));
    return 1;
}

static int qkd_get_new_key(QKDKEM_QKD_SESSION *session)
{
    qkd_key_request_t request = {0};
    qkd_key_container_t container = {0};
    qkd_key_t *key;
    uint32_t status;
    int ok = 0;

    request.number = 1;
    request.size = QKD_KEY_SIZE_BITS;
    status = GET_KEY(session->master_kme, session->slave_sae, &request,
                     &container);
    if (status != QKD_STATUS_OK || container.key_count < 1 || !container.keys)
        goto done;
    key = &container.keys[0];
    if (!key->key_ID || !uuid_parse_binary(key->key_ID, session->id)
        || !base64_decode_key(key->key, session->key))
        goto done;
    session->has_key = true;
    ok = 1;

done:
    qkd_key_container_free(&container);
    if (!ok)
        OPENSSL_cleanse(session->key, sizeof(session->key));
    return ok;
}

static int qkd_get_key_by_id(QKDKEM_QKD_SESSION *session)
{
    qkd_key_ids_t ids = {0};
    qkd_key_container_t container = {0};
    qkd_key_id_t id = {0};
    char text[37];
    uint32_t status;
    int ok = 0;

    uuid_format(session->id, text);
    id.key_ID = text;
    ids.key_ID_count = 1;
    ids.key_IDs = &id;
    status = GET_KEY_WITH_IDS(session->slave_kme, session->master_sae, &ids,
                              &container);
    if (status == QKD_STATUS_OK && container.key_count == 1 && container.keys
        && base64_decode_key(container.keys[0].key, session->key)) {
        session->has_key = true;
        ok = 1;
    }
    qkd_key_container_free(&container);
    if (!ok)
        OPENSSL_cleanse(session->key, sizeof(session->key));
    return ok;
}
#endif

QKDKEM_QKD_SESSION *qkdkem_qkd_session_new(bool initiator)
{
    QKDKEM_QKD_SESSION *session = OPENSSL_zalloc(sizeof(*session));

    if (!session)
        return NULL;
    session->initiator = initiator;

#ifdef ETSI_004_API
    session->source_uri = copy_environment("QKD_SOURCE_URI");
    session->destination_uri = copy_environment("QKD_DEST_URI");
    if (!session->source_uri || !session->destination_uri)
        goto error;

    session->qos.Key_chunk_size = QKD_KEY_SIZE;
    session->qos.Timeout = environment_u32("QKD_QOS_TIMEOUT", UINT32_C(60000));
    session->qos.Priority = environment_u32("QKD_QOS_PRIORITY", 0);
    session->qos.Max_bps = environment_u32("QKD_QOS_MAX_BPS", UINT32_C(40000));
    session->qos.Min_bps = environment_u32("QKD_QOS_MIN_BPS", UINT32_C(5000));
    session->qos.Jitter = environment_u32("QKD_QOS_JITTER", 10);
    session->qos.TTL = environment_u32("QKD_QOS_TTL", UINT32_C(3600));
    OPENSSL_strlcpy(session->qos.Metadata_mimetype, "application/json",
                    sizeof(session->qos.Metadata_mimetype));
    session->metadata.Metadata_size = QKD_METADATA_MAX_SIZE;
    session->metadata.Metadata_buffer = OPENSSL_zalloc(QKD_METADATA_MAX_SIZE);
    if (!session->metadata.Metadata_buffer)
        goto error;
    memcpy(session->metadata.Metadata_buffer, "{}", 2);
#else
    session->master_kme = copy_environment("QKD_MASTER_KME_HOSTNAME");
    session->slave_kme = copy_environment("QKD_SLAVE_KME_HOSTNAME");
    session->master_sae = copy_environment("QKD_MASTER_SAE");
    session->slave_sae = copy_environment("QKD_SLAVE_SAE");
    if (!session->master_kme || !session->slave_kme || !session->master_sae
        || !session->slave_sae)
        goto error;
#endif
    return session;

error:
    qkdkem_qkd_session_free(session);
    return NULL;
}

void qkdkem_qkd_session_free(QKDKEM_QKD_SESSION *session)
{
    if (!session)
        return;
#ifdef ETSI_004_API
    if (session->connected) {
        uint32_t status = 0;
        (void)CLOSE(session->id, &status);
    }
    OPENSSL_free(session->source_uri);
    OPENSSL_free(session->destination_uri);
    OPENSSL_clear_free(session->metadata.Metadata_buffer,
                       QKD_METADATA_MAX_SIZE);
#else
    OPENSSL_free(session->master_kme);
    OPENSSL_free(session->slave_kme);
    OPENSSL_free(session->master_sae);
    OPENSSL_free(session->slave_sae);
#endif
    OPENSSL_clear_free(session, sizeof(*session));
}

int qkdkem_qkd_offer_start(QKDKEM_QKD_SESSION *session,
                           unsigned char id[QKD_KSID_SIZE])
{
    if (!session || !session->initiator || !id)
        return 0;
#ifdef ETSI_004_API
    if (!qkd_open_session(session))
        return 0;
#else
    if (!qkd_get_new_key(session))
        return 0;
#endif
    memcpy(id, session->id, QKD_KSID_SIZE);
    return 1;
}

int qkdkem_qkd_offer_accept(QKDKEM_QKD_SESSION *session,
                            const unsigned char id[QKD_KSID_SIZE],
                            unsigned char key[QKD_KEY_SIZE])
{
    if (!session || session->initiator || !id || !key)
        return 0;
    memcpy(session->id, id, QKD_KSID_SIZE);
#ifdef ETSI_004_API
    if (!qkd_open_session(session) || !qkd_read_session_key(session))
        return 0;
#else
    if (!qkd_get_key_by_id(session))
        return 0;
#endif
    memcpy(key, session->key, QKD_KEY_SIZE);
    return 1;
}

int qkdkem_qkd_offer_finish(QKDKEM_QKD_SESSION *session,
                            unsigned char key[QKD_KEY_SIZE])
{
    if (!session || !session->initiator || !key)
        return 0;
#ifdef ETSI_004_API
    if (!session->has_key && !qkd_read_session_key(session))
        return 0;
#endif
    if (!session->has_key)
        return 0;
    memcpy(key, session->key, QKD_KEY_SIZE);
    return 1;
}

/*
 * The ETSI 004 variants below are retained to keep the adapter symmetric.
 * Provider builds cannot call them because ETSI 004 requires QKD_KEY_ID_CH.
 */
int qkdkem_qkd_response_create(QKDKEM_QKD_SESSION *session,
                               unsigned char id[QKD_KSID_SIZE],
                               unsigned char key[QKD_KEY_SIZE])
{
    if (!session || session->initiator || !id || !key)
        return 0;
#ifdef ETSI_004_API
    if (!qkd_open_session(session) || !qkd_read_session_key(session))
        return 0;
#else
    if (!qkd_get_new_key(session))
        return 0;
#endif
    memcpy(id, session->id, QKD_KSID_SIZE);
    memcpy(key, session->key, QKD_KEY_SIZE);
    return 1;
}

int qkdkem_qkd_response_accept(QKDKEM_QKD_SESSION *session,
                               const unsigned char id[QKD_KSID_SIZE],
                               unsigned char key[QKD_KEY_SIZE])
{
    if (!session || !session->initiator || !id || !key)
        return 0;
    memcpy(session->id, id, QKD_KSID_SIZE);
#ifdef ETSI_004_API
    if (!qkd_open_session(session) || !qkd_read_session_key(session))
        return 0;
#else
    if (!qkd_get_key_by_id(session))
        return 0;
#endif
    memcpy(key, session->key, QKD_KEY_SIZE);
    return 1;
}
