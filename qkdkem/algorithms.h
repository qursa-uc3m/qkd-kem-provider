/* SPDX-License-Identifier: MIT */
#ifndef QKDKEM_ALGORITHMS_H
#define QKDKEM_ALGORITHMS_H

/*
 * token, public name, group id, security bits, inner EVP aliases, env suffix
 *
 * Existing qkd_* names and code points retain their v1 values.  eFrodoKEM
 * groups use deterministic private-use code points and are new in v2.
 */
#define QKDKEM_ALGORITHM_LIST(X)                                               \
    X(efrodo640aes, "qkd_efrodo640aes", 0xfe00, 128, "efrodo640aes", NULL,     \
      NULL, "EFRODO640AES")                                                    \
    X(efrodo640shake, "qkd_efrodo640shake", 0xfe01, 128, "efrodo640shake",     \
      NULL, NULL, "EFRODO640SHAKE")                                            \
    X(efrodo976aes, "qkd_efrodo976aes", 0xfe02, 192, "efrodo976aes", NULL,     \
      NULL, "EFRODO976AES")                                                    \
    X(efrodo976shake, "qkd_efrodo976shake", 0xfe03, 192, "efrodo976shake",     \
      NULL, NULL, "EFRODO976SHAKE")                                            \
    X(efrodo1344aes, "qkd_efrodo1344aes", 0xfe04, 256, "efrodo1344aes", NULL,  \
      NULL, "EFRODO1344AES")                                                   \
    X(efrodo1344shake, "qkd_efrodo1344shake", 0xfe05, 256, "efrodo1344shake",  \
      NULL, NULL, "EFRODO1344SHAKE")                                           \
    X(frodo640aes, "qkd_frodo640aes", 0x3000, 128, "frodo640aes", NULL, NULL,  \
      "FRODO640AES")                                                           \
    X(frodo640shake, "qkd_frodo640shake", 0x3001, 128, "frodo640shake", NULL,  \
      NULL, "FRODO640SHAKE")                                                   \
    X(frodo976aes, "qkd_frodo976aes", 0x3002, 192, "frodo976aes", NULL, NULL,  \
      "FRODO976AES")                                                           \
    X(frodo976shake, "qkd_frodo976shake", 0x3003, 192, "frodo976shake", NULL,  \
      NULL, "FRODO976SHAKE")                                                   \
    X(frodo1344aes, "qkd_frodo1344aes", 0x3004, 256, "frodo1344aes", NULL,     \
      NULL, "FRODO1344AES")                                                    \
    X(frodo1344shake, "qkd_frodo1344shake", 0x3005, 256, "frodo1344shake",     \
      NULL, NULL, "FRODO1344SHAKE")                                            \
    X(kyber512, "qkd_kyber512", 0x303a, 128, "kyber512", "Kyber512", NULL,     \
      "KYBER512")                                                              \
    X(kyber768, "qkd_kyber768", 0x303c, 192, "kyber768", "Kyber768", NULL,     \
      "KYBER768")                                                              \
    X(kyber1024, "qkd_kyber1024", 0x303d, 256, "kyber1024", "Kyber1024", NULL, \
      "KYBER1024")                                                             \
    X(mlkem512, "qkd_mlkem512", 0x304a, 128, "ML-KEM-512", "mlkem512", NULL,   \
      "MLKEM512")                                                              \
    X(mlkem768, "qkd_mlkem768", 0x3768, 192, "ML-KEM-768", "mlkem768", NULL,   \
      "MLKEM768")                                                              \
    X(mlkem1024, "qkd_mlkem1024", 0x3024, 256, "ML-KEM-1024", "mlkem1024",     \
      NULL, "MLKEM1024")                                                       \
    X(bikel1, "qkd_bikel1", 0x3041, 128, "bikel1", NULL, NULL, "BIKEL1")       \
    X(bikel3, "qkd_bikel3", 0x3042, 192, "bikel3", NULL, NULL, "BIKEL3")       \
    X(bikel5, "qkd_bikel5", 0x3043, 256, "bikel5", NULL, NULL, "BIKEL5")       \
    X(hqc128, "qkd_hqc128", 0x3044, 128, "hqc1", "hqc128", NULL, "HQC128")     \
    X(hqc192, "qkd_hqc192", 0x3045, 192, "hqc3", "hqc192", NULL, "HQC192")     \
    X(hqc256, "qkd_hqc256", 0x3046, 256, "hqc5", "hqc256", NULL, "HQC256")

#endif
