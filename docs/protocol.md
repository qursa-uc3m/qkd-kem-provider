# Protocol

Each `qkd_<kem>` algorithm is exposed as one ephemeral TLS 1.3 KEM group. The
provider owns the QKD exchange and delegates the post-quantum component to an
independently loaded OpenSSL provider through EVP.

## Components and roles

The two TLS peers derive their QKD roles from the KEM operation; no process-wide
client/server flag is needed:

| OpenSSL object | TLS use | QKD role |
| --- | --- | --- |
| locally generated private key | produces a key share and later decapsulates | offer initiator |
| imported peer public key | encapsulates to the received key share | offer responder |

This remains correct when client and server run in the same process and during
HelloRetryRequest, because the role belongs to the key object rather than the
process.

Consequently, encapsulation requires an imported peer public key. Attempting
the common single-key EVP loopback pattern—encapsulating and decapsulating with
the same locally generated `EVP_PKEY`—is rejected with an OpenSSL error. Export
and import the public share into a separate `EVP_PKEY`, as a real TLS peer does.

The inner KEM is selected from the aliases in `qkdkem/algorithms.h`. Fetches use
`provider!=qkdkemprovider` by default to prevent recursion. The optional
`QKDKEM_INNER_PROPERTIES` query can select a specific peer provider. A TLS group
is advertised only if at least one of its inner aliases can be fetched.

## Wire format

The public key share and KEM outputs preserve the version 0.1.x ordering:

```text
key_share  = pq_public     || qkd_key_id
ciphertext = pq_ciphertext || qkd_key_id
secret     = pq_secret     || qkd_key
```

`qkd_key_id` is always 16 bytes and `qkd_key` is 32 bytes. PQ component sizes
come from the selected inner provider and are checked before allocation and
concatenation.

With `QKD_KEY_ID_CH=OFF`, the key-share suffix is zero and the encapsulating
peer obtains the QKD key and identifier. The identifier is carried in the
ciphertext so the decapsulating peer can retrieve the same key. This mode is
available with ETSI 014.

With `QKD_KEY_ID_CH=ON`, key generation reserves the QKD identifier and carries
it in the key share. Encapsulation accepts that offer and the private-key owner
finishes it during decapsulation. The ciphertext retains the same 16-byte
suffix for 0.1.x wire-length compatibility and fills it with the key-share
identifier. ETSI 004 requires this mode because both peers must join the stream
before `GET_KEY` can succeed.

## Operation sequence

1. The key-share peer fetches the inner KEM and generates an `EVP_PKEY`.
2. The composite key-management implementation exports `pq_public` followed by
   the QKD identifier field.
3. The encapsulating peer imports the share, obtains the PQ ciphertext and
   secret with `EVP_PKEY_encapsulate()`, and completes the matching QKD action.
4. The private-key peer splits the ciphertext, calls
   `EVP_PKEY_decapsulate()`, and retrieves or finishes the QKD key.
5. Both sides pass `pq_secret || qkd_key` to the TLS 1.3 key schedule.

Failures are fail-closed: unavailable inner algorithms are not advertised,
malformed composite keys are rejected, output capacities are checked, and QKD
material is cleansed when its key or operation context is released.

PQ encapsulation and decapsulation run before QKD retrieval, so an inner-KEM
failure does not consume scarce QKD material. In key-ID-in-ClientHello mode,
however, generating a key share necessarily reserves or retrieves QKD material;
an abandoned HelloRetryRequest share cannot be returned through ETSI 014.

QKD identifiers in ClientHello are unauthenticated at the time the responder
processes them. A replay can therefore cause a lookup at the slave KME. KME
deployments should enforce one-time identifiers, authentication, rate limits,
and bounded request timeouts. The provider compares the ciphertext identifier
with the original key-share identifier before decapsulation, catching replay,
cross-session substitution, and mode mismatch as early as possible.

## Combiner compatibility

Version 0.2.0 deliberately keeps direct concatenation. Introducing a KDF-based
hybrid combiner would change the derived TLS secret and therefore requires a new
group definition and interoperability contract rather than an implementation
refactor.
