# Migration from v1

Version 2 replaces the oqsprovider fork with a provider-to-provider design.

Release summary: **delegate PQ KEM operations to another OpenSSL provider via
EVP, retaining the QKD protocol and the 0.1.x TLS wire layout.**

- PQ key generation and KEM operations are delegated through EVP.
- `OQSX_KEY`, component pointer arrays, internal length headers, liboqs calls,
  encoders, decoders, OIDs, and signature support were removed.
- The build now depends on OpenSSL and the QKD ETSI wrapper, not liboqs.
- TLS capabilities are dynamic: a `qkd_*` group is advertised only when its
  inner KEM is available from an active peer provider.
- Existing v1 group names, assigned experimental code points, public-share
  ordering, ciphertext ordering, and secret ordering are preserved.
- The historical `OQS_CODEPOINT_QKD_*` overrides continue to work; new builds
  should use `QKDKEM_CODEPOINT_*`.
- eFrodoKEM groups are new and use TLS private-use code points `0xfe00` through
  `0xfe05`.
- ETSI 004 now rejects `QKD_KEY_ID_CH=OFF` at configure time. That combination
  cannot complete its two-party stream setup before synchronous encapsulation;
  ETSI 014 continues to support both layouts.

The provider no longer serializes ephemeral KEM keys. Applications that used
the removed PEM/DER surface must keep those keys in the peer PQ provider or use
a separate persistence format.
