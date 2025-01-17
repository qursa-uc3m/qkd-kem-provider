Algorithms supported
====================

This page lists all quantum-safe algorithms supported by qkd-kem-provider.

# Code points / algorithm IDs

<!--- OQS_TEMPLATE_FRAGMENT_IDS_START -->
|Algorithm name | default ID | enabled | environment variable |
|---------------|:----------:|:-------:|----------------------|
| qkd_frodo640aes | 0x3000 | Yes | OQS_CODEPOINT_QKD_FRODO640AES |
| qkd_frodo640shake | 0x3001 | Yes | OQS_CODEPOINT_QKD_FRODO640SHAKE |
| qkd_frodo976aes | 0x3002 | Yes | OQS_CODEPOINT_QKD_FRODO976AES |
| qkd_frodo976shake | 0x3003 | Yes | OQS_CODEPOINT_QKD_FRODO976SHAKE |
| qkd_frodo1344aes | 0x3004 | Yes | OQS_CODEPOINT_QKD_FRODO1344AES |
| qkd_frodo1344shake | 0x3005 | Yes | OQS_CODEPOINT_QKD_FRODO1344SHAKE |
| qkd_kyber512 | 0x303A | Yes | OQS_CODEPOINT_QKD_KYBER512 |
| qkd_kyber768 | 0x303C | Yes | OQS_CODEPOINT_QKD_KYBER768 |
| qkd_kyber1024 | 0x303D | Yes | OQS_CODEPOINT_QKD_KYBER1024 |
| qkd_mlkem512 | 0x304A | Yes | OQS_CODEPOINT_QKD_MLKEM512 |
| qkd_mlkem768 | 0x3768 | Yes | OQS_CODEPOINT_QKD_MLKEM768 |
| qkd_mlkem1024 | 0x3024 | Yes | OQS_CODEPOINT_QKD_MLKEM1024 |
| qkd_bikel1 | 0x3041 | Yes | OQS_CODEPOINT_QKD_BIKEL1 |
| qkd_bikel3 | 0x3042 | Yes | OQS_CODEPOINT_QKD_BIKEL3 |
| qkd_bikel5 | 0x3043 | Yes | OQS_CODEPOINT_QKD_BIKEL5 |
| qkd_hqc128 | 0x3044 | Yes | OQS_CODEPOINT_QKD_HQC128 |
| qkd_hqc192 | 0x3045 | Yes | OQS_CODEPOINT_QKD_HQC192 |
| qkd_hqc256 | 0x3046 | Yes | OQS_CODEPOINT_QKD_HQC256 |
<!--- OQS_TEMPLATE_FRAGMENT_IDS_END -->

# OIDs

Along the same lines as the code points, X.509 OIDs may be subject to change
prior to final standardization. The environment variables below permit
adapting the OIDs of all supported signature algorithms as per the table below.
OIDs denoted with NULL are not maintained and may lead to errors in code
execution. Anyone interested in using an algorithm with such designation is
requested to contribute to the maintenance of these OIDs along the lines
discussed in https://github.com/open-quantum-safe/oqs-provider/issues/351.

If [OQS_KEM_ENCODERS](CONFIGURE.md#OQS_KEM_ENCODERS) is enabled the following list is also available:

|Algorithm name |    default OID    | environment variable |
|---------------|:-----------------:|----------------------|
| qkd_frodo640aes | NULL | OQS_OID_QKD_FRODO640AES
| qkd_frodo640shake | NULL | OQS_OID_QKD_FRODO640SHAKE
| qkd_frodo976aes | NULL | OQS_OID_QKD_FRODO976AES
| qkd_frodo976shake | NULL | OQS_OID_QKD_FRODO976SHAKE
| qkd_frodo1344aes | NULL | OQS_OID_QKD_FRODO1344AES
| qkd_frodo1344shake | NULL | OQS_OID_QKD_FRODO1344SHAKE
| qkd_kyber512 | NULL | OQS_OID_QKD_KYBER512 
| qkd_kyber768| NULL | OQS_OID_QKD_KYBER768 
| qkd_kyber1024 | NULL| OQS_OID_QKD_KYBER1024 
| qkd_mlkem512 | NULL | OQS_OID_QKD_MLKEM512 
| qkd_mlkem768 | NULL | OQS_OID_QKD_MLKEM768 
| qkd_mlkem1024 | NULL | OQS_OID_QKD_MLKEM1024 
| qkd_bikel1 | NULL | OQS_OID_QKD_BIKEL1 
| qkd_bikel3 | NULL | OQS_OID_QKD_BIKEL3 
| qkd_bikel5 | NULL | OQS_OID_QKD_BIKEL5 
| qkd_hqc128 | NULL | OQS_OID_QKD_HQC128 
| qkd_hqc192 | NULL | OQS_OID_QKD_HQC192 
| qkd_hqc256 | NULL | OQS_OID_QKD_HQC256
<!--- OQS_TEMPLATE_FRAGMENT_OIDS_END -->