// SPDX-License-Identifier: Apache-2.0 AND MIT

/*
 * OQS OpenSSL 3 provider
 *
 * Code strongly inspired by OpenSSL legacy provider.
 *
 */

#include <errno.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <stdio.h>
#include <string.h>

#include "oqs_prov.h"
#include "oqs_qkd_kem.h"
#include <qkd-etsi-api-c-wrapper/qkd_etsi_api.h>
#ifdef ETSI_004_API
#include <qkd-etsi-api-c-wrapper/etsi004/api.h>
#elif defined(ETSI_014_API)
#include <qkd-etsi-api-c-wrapper/etsi014/api.h>
#endif

#ifdef NDEBUG
#define OQS_PROV_PRINTF(a)
#define OQS_PROV_PRINTF2(a, b)
#define OQS_PROV_PRINTF3(a, b, c)
#else
#define OQS_PROV_PRINTF(a)                                                     \
    if (getenv("OQSPROV"))                                                     \
    printf(a)
#define OQS_PROV_PRINTF2(a, b)                                                 \
    if (getenv("OQSPROV"))                                                     \
    printf(a, b)
#define OQS_PROV_PRINTF3(a, b, c)                                              \
    if (getenv("OQSPROV"))                                                     \
    printf(a, b, c)
#endif // NDEBUG

/*
 * Forward declarations to ensure that interface functions are correctly
 * defined.
 */
static OSSL_FUNC_provider_gettable_params_fn oqsprovider_gettable_params;
static OSSL_FUNC_provider_get_params_fn oqsprovider_get_params;
static OSSL_FUNC_provider_query_operation_fn oqsprovider_query;
extern OSSL_FUNC_provider_get_capabilities_fn oqs_provider_get_capabilities;

/*
 * List of all algorithms with given OIDs
 */
///// OQS_TEMPLATE_FRAGMENT_ASSIGN_SIG_OIDS_START

#ifdef OQS_KEM_ENCODERS
#define OQS_OID_CNT 220
#else
#define OQS_OID_CNT 114
#endif
const char *oqs_oid_alg_list[OQS_OID_CNT] = {

#ifdef OQS_KEM_ENCODERS
    NULL, "qkd_frodo640aes",  NULL, "qkd_frodo640shake",
    NULL, "qkd_frodo976aes",  NULL, "qkd_frodo976shake",
    NULL, "qkd_frodo1344aes", NULL, "qkd_frodo1344shake",
    NULL, "qkd_kyber512",     NULL, "qkd_kyber768",
    NULL, "qkd_kyber1024",    NULL, "qkd_mlkem512",
    NULL, "qkd_mlkem768",     NULL, "qkd_mlkem1024",
    NULL, "qkd_bikel1",       NULL, "qkd_bikel3",
    NULL, "qkd_bikel5",       NULL, "qkd_hqc128",
    NULL, "qkd_hqc192",       NULL, "qkd_hqc256",

#endif /* OQS_KEM_ENCODERS */
};

int oqs_patch_oids(void) {
    {
        const char *envval = NULL;

#ifdef OQS_KEM_ENCODERS
        if ((envval = getenv("OQS_OID_QKD_FRODO640AES")))
            oqs_oid_alg_list[0] = envval;
        if ((envval = getenv("OQS_OID_QKD_FRODO640SHAKE")))
            oqs_oid_alg_list[2] = envval;
        if ((envval = getenv("OQS_OID_QKD_FRODO976AES")))
            oqs_oid_alg_list[4] = envval;
        if ((envval = getenv("OQS_OID_QKD_FRODO976SHAKE")))
            oqs_oid_alg_list[6] = envval;
        if ((envval = getenv("OQS_OID_QKD_FRODO1344AES")))
            oqs_oid_alg_list[8] = envval;
        if ((envval = getenv("OQS_OID_QKD_FRODO1344SHAKE")))
            oqs_oid_alg_list[10] = envval;
        if ((envval = getenv("OQS_OID_QKD_KYBER512")))
            oqs_oid_alg_list[12] = envval;
        if ((envval = getenv("OQS_OID_QKD_KYBER768")))
            oqs_oid_alg_list[14] = envval;
        if ((envval = getenv("OQS_OID_QKD_KYBER1024")))
            oqs_oid_alg_list[16] = envval;
        if ((envval = getenv("OQS_OID_QKD_MLKEM512")))
            oqs_oid_alg_list[18] = envval;
        if ((envval = getenv("OQS_OID_QKD_MLKEM768")))
            oqs_oid_alg_list[20] = envval;
        if ((envval = getenv("OQS_OID_QKD_MLKEM1024")))
            oqs_oid_alg_list[2] = envval;
        if ((envval = getenv("OQS_OID_QKD_BIKEL1")))
            oqs_oid_alg_list[24] = envval;
        if ((envval = getenv("OQS_OID_QKD_BIKEL3")))
            oqs_oid_alg_list[26] = envval;
        if ((envval = getenv("OQS_OID_QKD_BIKEL5")))
            oqs_oid_alg_list[28] = envval;
        if ((envval = getenv("OQS_OID_QKD_HQC128")))
            oqs_oid_alg_list[30] = envval;
        if ((envval = getenv("OQS_OID_QKD_HQC192")))
            oqs_oid_alg_list[32] = envval;
        if ((envval = getenv("OQS_OID_QKD_HQC256")))
            oqs_oid_alg_list[34] = envval;

#define OQS_KEMOID_CNT 104 + 2
#else
#define OQS_KEMOID_CNT 0
#endif /* OQS_KEM_ENCODERS */
    } ///// OQS_TEMPLATE_FRAGMENT_OID_PATCHING_END
    return 1;
}

#define KEMQKDALG(NAMES, SECBITS)                                              \
    {"qkd_" #NAMES "",                                                         \
     "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "",            \
     oqs_qkd_kem_functions},

#define KEMKMQKDALG(NAMES, SECBITS)                                            \
    {"qkd_" #NAMES "",                                                         \
     "provider=oqsprovider,oqsprovider.security_bits=" #SECBITS "",            \
     oqs_qkd_##NAMES##_keymgmt_functions},

/* Functions provided by the core */
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;

/* Parameters we provide to the core */
static const OSSL_PARAM oqsprovider_param_types[] = {
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_ALGORITHM oqsprovider_asym_kems[] = {
///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_START
// clang-format off
#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    KEMQKDALG(frodo640aes, 128)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    KEMQKDALG(frodo640shake, 128)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    KEMQKDALG(frodo976aes, 192)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    KEMQKDALG(frodo976shake, 192)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    KEMQKDALG(frodo1344aes, 256)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    KEMQKDALG(frodo1344shake, 256)
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMQKDALG(kyber512, 128)
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMQKDALG(kyber768, 192)
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMQKDALG(kyber1024, 256)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
    KEMQKDALG(mlkem512, 128)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    KEMQKDALG(mlkem768, 192)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    KEMQKDALG(mlkem1024, 256)
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    KEMQKDALG(bikel1, 128)
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    KEMQKDALG(bikel3, 192)
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    KEMQKDALG(bikel5, 256)
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    KEMQKDALG(hqc128, 128)
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    KEMQKDALG(hqc192, 192)
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    KEMQKDALG(hqc256, 256)
#endif
    // clang-format on
    ///// OQS_TEMPLATE_FRAGMENT_KEM_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM oqsprovider_keymgmt[] = {
///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_START
// clang-format off

#ifdef OQS_ENABLE_KEM_frodokem_640_aes
    KEMKMQKDALG(frodo640aes, 128)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_640_shake
    KEMKMQKDALG(frodo640shake, 128)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_aes
    KEMKMQKDALG(frodo976aes, 192)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_976_shake
    KEMKMQKDALG(frodo976shake, 192)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_aes
    KEMKMQKDALG(frodo1344aes, 256)
#endif
#ifdef OQS_ENABLE_KEM_frodokem_1344_shake
    KEMKMQKDALG(frodo1344shake, 256)
#endif
#ifdef OQS_ENABLE_KEM_kyber_512
    KEMKMQKDALG(kyber512, 128)
#endif
#ifdef OQS_ENABLE_KEM_kyber_768
    KEMKMQKDALG(kyber768, 192)
#endif
#ifdef OQS_ENABLE_KEM_kyber_1024
    KEMKMQKDALG(kyber1024, 256)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_512
    KEMKMQKDALG(mlkem512, 128)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_768
    KEMKMQKDALG(mlkem768, 192)
#endif
#ifdef OQS_ENABLE_KEM_ml_kem_1024
    KEMKMQKDALG(mlkem1024, 256)
#endif
#ifdef OQS_ENABLE_KEM_bike_l1
    KEMKMQKDALG(bikel1, 128)
#endif
#ifdef OQS_ENABLE_KEM_bike_l3
    KEMKMQKDALG(bikel3, 192)
#endif
#ifdef OQS_ENABLE_KEM_bike_l5
    KEMKMQKDALG(bikel5, 256)
#endif
#ifdef OQS_ENABLE_KEM_hqc_128
    KEMKMQKDALG(hqc128, 128)
#endif
#ifdef OQS_ENABLE_KEM_hqc_192
    KEMKMQKDALG(hqc192, 192)
#endif
#ifdef OQS_ENABLE_KEM_hqc_256
    KEMKMQKDALG(hqc256, 256)
#endif
    // clang-format on
    ///// OQS_TEMPLATE_FRAGMENT_KEYMGMT_FUNCTIONS_END
    {NULL, NULL, NULL}};

static const OSSL_ALGORITHM oqsprovider_encoder[] = {
#define ENCODER_PROVIDER "oqsprovider"
#include "oqsencoders.inc"
    {NULL, NULL, NULL}
#undef ENCODER_PROVIDER
};

static const OSSL_ALGORITHM oqsprovider_decoder[] = {
#define DECODER_PROVIDER "oqsprovider"
#include "oqsdecoders.inc"
    {NULL, NULL, NULL}
#undef DECODER_PROVIDER
};

// get the last number on the composite OID
int get_composite_idx(char *name) {
    char *s = NULL;
    int i, len, ret = -1, count = 0;

    for (i = 1; i <= OQS_OID_CNT; i += 2) {
        if (!strcmp((char *)oqs_oid_alg_list[i], name)) {
            s = (char *)oqs_oid_alg_list[i - 1];
            break;
        }
    }
    if (s == NULL) {
        return ret;
    }

    len = strlen(s);

    for (i = 0; i < len; i++) {
        if (s[i] == '.') {
            count += 1;
        }
        if (count == 8) { // 8 dots in composite OID
            errno = 0;
            ret = strtol(s + i + 1, NULL, 10);
            if (errno == ERANGE)
                ret = -1;
            break;
        }
    }
    return ret;
}

static const OSSL_PARAM *oqsprovider_gettable_params(void *provctx) {
    return oqsprovider_param_types;
}

#define OQS_PROVIDER_BASE_BUILD_INFO_STR                                       \
    "OQS Provider v." OQS_PROVIDER_VERSION_STR OQS_PROVIDER_COMMIT             \
    " based on liboqs v." OQS_VERSION_TEXT

#ifdef QSC_ENCODING_VERSION_STRING
#define OQS_PROVIDER_BUILD_INFO_STR                                            \
    OQS_PROVIDER_BASE_BUILD_INFO_STR                                           \
    " using qsc-key-encoder v." QSC_ENCODING_VERSION_STRING
#else
#define OQS_PROVIDER_BUILD_INFO_STR OQS_PROVIDER_BASE_BUILD_INFO_STR
#endif

static int oqsprovider_get_params(void *provctx, OSSL_PARAM params[]) {
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "OpenSSL QKD-KEM Provider"))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OQS_PROVIDER_VERSION_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, OQS_PROVIDER_BUILD_INFO_STR))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
    if (p != NULL && !OSSL_PARAM_set_int(p, 1)) // provider is always running
        return 0;
    // not passing in params to respond to is no error; response is empty then
    return 1;
}

static const OSSL_ALGORITHM *oqsprovider_query(void *provctx, int operation_id,
                                               int *no_cache) {
    *no_cache = 0;

    switch (operation_id) {
    case OSSL_OP_KEM:
        return oqsprovider_asym_kems;
    case OSSL_OP_KEYMGMT:
        return oqsprovider_keymgmt;
    case OSSL_OP_ENCODER:
        return oqsprovider_encoder;
    case OSSL_OP_DECODER:
        return oqsprovider_decoder;
    default:
        if (getenv("OQSPROV"))
            printf("Unknown operation %d requested from OQS provider\n",
                   operation_id);
    }
    return NULL;
}

static void oqsprovider_teardown(void *provctx) {
    oqsx_freeprovctx((PROV_OQS_CTX *)provctx);
    OQS_destroy();
}

/* Functions we provide to the core */
static const OSSL_DISPATCH oqsprovider_dispatch_table[] = {
    {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))oqsprovider_teardown},
    {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS,
     (void (*)(void))oqsprovider_gettable_params},
    {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))oqsprovider_get_params},
    {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))oqsprovider_query},
    {OSSL_FUNC_PROVIDER_GET_CAPABILITIES,
     (void (*)(void))oqs_provider_get_capabilities},
    {0, NULL}};

#ifdef OQS_PROVIDER_STATIC
#define OQS_PROVIDER_ENTRYPOINT_NAME oqs_provider_init
#else
#define OQS_PROVIDER_ENTRYPOINT_NAME OSSL_provider_init
#endif // ifdef OQS_PROVIDER_STATIC

int OQS_PROVIDER_ENTRYPOINT_NAME(const OSSL_CORE_HANDLE *handle,
                                 const OSSL_DISPATCH *in,
                                 const OSSL_DISPATCH **out, void **provctx) {
    const OSSL_DISPATCH *orig_in = in;
    OSSL_FUNC_core_obj_create_fn *c_obj_create = NULL;

    OSSL_FUNC_core_obj_add_sigid_fn *c_obj_add_sigid = NULL;
    BIO_METHOD *corebiometh;
    OSSL_LIB_CTX *libctx = NULL;
    int i, rc = 0;
    char *opensslv;
    const char *ossl_versionp = NULL;
    OSSL_PARAM version_request[] = {{"openssl-version", OSSL_PARAM_UTF8_PTR,
                                     &opensslv, sizeof(&opensslv), 0},
                                    {NULL, 0, NULL, 0, 0}};

    OQS_init();

    if (!oqs_prov_bio_from_dispatch(in))
        goto end_init;

    if (!oqs_patch_codepoints())
        goto end_init;

    if (!oqs_patch_oids())
        goto end_init;

    for (; in->function_id != 0; in++) {
        switch (in->function_id) {
        case OSSL_FUNC_CORE_GETTABLE_PARAMS:
            c_gettable_params = OSSL_FUNC_core_gettable_params(in);
            break;
        case OSSL_FUNC_CORE_GET_PARAMS:
            c_get_params = OSSL_FUNC_core_get_params(in);
            break;
        case OSSL_FUNC_CORE_OBJ_CREATE:
            c_obj_create = OSSL_FUNC_core_obj_create(in);
            break;
        case OSSL_FUNC_CORE_OBJ_ADD_SIGID:
            c_obj_add_sigid = OSSL_FUNC_core_obj_add_sigid(in);
            break;
        /* Just ignore anything we don't understand */
        default:
            break;
        }
    }

    // we need these functions:
    if (c_obj_create == NULL || c_obj_add_sigid == NULL || c_get_params == NULL)
        goto end_init;

    // we need to know the version of the calling core to activate
    // suitable bug workarounds
    if (c_get_params(handle, version_request)) {
        ossl_versionp = *(void **)version_request[0].data;
    }

    // insert all OIDs to the global objects list
    for (i = 0; i < OQS_OID_CNT; i += 2) {
        if (oqs_oid_alg_list[i] == NULL) {
            OQS_PROV_PRINTF2("OQS PROV: Warning: No OID registered for %s\n",
                             oqs_oid_alg_list[i + 1]);
        } else {
            if (!c_obj_create(handle, oqs_oid_alg_list[i],
                              oqs_oid_alg_list[i + 1],
                              oqs_oid_alg_list[i + 1])) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
                fprintf(stderr, "error registering NID for %s\n",
                        oqs_oid_alg_list[i + 1]);
                goto end_init;
            }

            /* create object (NID) again to avoid setup corner case problems
             * see https://github.com/openssl/openssl/discussions/21903
             * Not testing for errors is intentional.
             * At least one core version hangs up; so don't do this there:
             */
            if (strcmp("3.1.0", ossl_versionp)) {
                ERR_set_mark();
                OBJ_create(oqs_oid_alg_list[i], oqs_oid_alg_list[i + 1],
                           oqs_oid_alg_list[i + 1]);
                ERR_pop_to_mark();
            }

            if (!oqs_set_nid((char *)oqs_oid_alg_list[i + 1],
                             OBJ_sn2nid(oqs_oid_alg_list[i + 1]))) {
                ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
                goto end_init;
            }

            if (!c_obj_add_sigid(handle, oqs_oid_alg_list[i + 1], "",
                                 oqs_oid_alg_list[i + 1])) {
                fprintf(stderr, "error registering %s with no hash\n",
                        oqs_oid_alg_list[i + 1]);
                ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
                goto end_init;
            }

            if (OBJ_sn2nid(oqs_oid_alg_list[i + 1]) != 0) {
                OQS_PROV_PRINTF3(
                    "OQS PROV: successfully registered %s with NID %d\n",
                    oqs_oid_alg_list[i + 1],
                    OBJ_sn2nid(oqs_oid_alg_list[i + 1]));
            } else {
                fprintf(stderr,
                        "OQS PROV: Impossible error: NID unregistered "
                        "for %s.\n",
                        oqs_oid_alg_list[i + 1]);
                ERR_raise(ERR_LIB_USER, OQSPROV_R_OBJ_CREATE_ERR);
                goto end_init;
            }
        }
    }

    // if libctx not yet existing, create a new one
    if (((corebiometh = oqs_bio_prov_init_bio_method()) == NULL) ||
        ((libctx = OSSL_LIB_CTX_new_child(handle, orig_in)) == NULL) ||
        ((*provctx = oqsx_newprovctx(libctx, handle, corebiometh)) == NULL)) {
        OQS_PROV_PRINTF("OQS PROV: error creating new provider context\n");
        ERR_raise(ERR_LIB_USER, OQSPROV_R_LIB_CREATE_ERR);
        goto end_init;
    }

    *out = oqsprovider_dispatch_table;

    // finally, warn if neither default nor fips provider are present:
    if (!OSSL_PROVIDER_available(libctx, "default") &&
        !OSSL_PROVIDER_available(libctx, "fips")) {
        OQS_PROV_PRINTF(
            "OQS PROV: Default and FIPS provider not available. Errors "
            "may result.\n");
    } else {
        OQS_PROV_PRINTF("OQS PROV: Default or FIPS provider available.\n");
    }
    rc = 1;

end_init:
    if (!rc) {
        if (ossl_versionp) {
            OQS_PROV_PRINTF2(
                "oqsprovider init failed for OpenSSL core version %s\n",
                ossl_versionp);
        } else
            OQS_PROV_PRINTF("oqsprovider init failed for OpenSSL\n");
        if (libctx)
            OSSL_LIB_CTX_free(libctx);
        if (provctx && *provctx) {
            oqsprovider_teardown(*provctx);
            *provctx = NULL;
        }
    }
    return rc;
}
