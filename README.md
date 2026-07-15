# QKD-KEM provider

`qkdkemprovider` is a small OpenSSL 3 provider for TLS 1.3 groups that combine
QKD material with a post-quantum KEM. It uses **provider-to-provider**
composition: the QKD half is implemented here and the PQ half is fetched
through EVP from another active provider.

There is no liboqs build dependency and no copied provider implementation.
OpenSSL 3.5's default provider supplies ML-KEM. Activating `oqsprovider`
alongside this provider adds whichever FrodoKEM, eFrodoKEM, BIKE, HQC, legacy
Kyber, or ML-KEM implementations it exposes.

## Build

Requirements:

- OpenSSL 3.x or 4.x
- `qkd-etsi-api-c-wrapper`

If the QKD wrapper is checked out next to this repository, CMake finds it
automatically. Otherwise install it or set `QKD_ETSI_API_SOURCE_DIR`.

```sh
cmake -S . -B build \
  -DETSI_014_API=ON \
  -DETSI_004_API=OFF \
  -DQKD_BACKEND=simulated
cmake --build build
ctest --test-dir build --output-on-failure
```

`QKD_KEY_ID_CH=OFF` retains the default v1 layout, where the QKD identifier is
returned with the KEM ciphertext. Set it to `ON` to carry the identifier in the
TLS key share. Existing `qkd_*` names, code points, ciphertext ordering, and
shared-secret ordering are retained.

ETSI 004 requires `QKD_KEY_ID_CH=ON`: the stream identifier must reach the
peer before either side can retrieve stream key material.

## Use

For the simulated ETSI 014 backend:

```sh
source scripts/env.sh
openssl list -tls-groups -tls1_3 \
  -provider default -provider qkdkemprovider
```

On OpenSSL 3.5+ and 4.x this advertises `qkd_mlkem512`, `qkd_mlkem768`, and
`qkd_mlkem1024`. To use non-native algorithms, also activate an installed
`oqsprovider`:

```sh
openssl list -tls-groups -tls1_3 \
  -provider default -provider oqsprovider -provider qkdkemprovider
```

Only groups whose inner KEM can be fetched are advertised to TLS. Set
`QKDKEM_INNER_PROPERTIES` to constrain the peer provider, for example
`provider=oqsprovider` or `provider=default`.

Code points can be overridden with `QKDKEM_CODEPOINT_<ALGORITHM>`. The legacy
`OQS_CODEPOINT_QKD_<ALGORITHM>` variables remain accepted.

See [the protocol](docs/protocol.md) and [the v1 migration note](docs/migration.md).

## Version compatibility

| Provider | QKD ETSI wrapper | Composition |
| --- | --- | --- |
| 0.1.0 | 0.1.0 | bundled oqsprovider fork |
| 0.1.1 | 0.1.1 | bundled oqsprovider fork |
| 0.2.0 | 0.1.1 | provider-to-provider EVP delegation |

## Scope

The provider intentionally supports ephemeral TLS KEM keys only. It does not
implement certificate keys, PEM/DER encoding, signatures, or direct liboqs
calls.
