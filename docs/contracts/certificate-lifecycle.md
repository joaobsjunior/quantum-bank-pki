# Certificate Lifecycle Contract

Requirement: CONT-01, PKI-03

Owner: Quantum Bank PKI

This contract defines how the PKI layer owns mobile client certificate issuance,
renewal, revocation, and trust material for Quantum Bank local v1.

## PKI Ownership

The PKI layer owns certificate lifecycle decisions and certificate authority
integration.

KrakenD consumes and enforces certificates but does not own certificate
issuance, renewal, or revocation. Backend services validate OTK and CSR inputs
before handoff, but they do not act as certificate authorities.

The PKI owner is responsible for:

- Certificate profile definitions.
- CSR intake policy after backend validation.
- Certificate issuance.
- Certificate renewal.
- Certificate revocation.
- Trust anchor publication.
- Local development CA material.
- Fallback implementation selection.

## Transport Algorithm Policy

The PKI is post-quantum first (NIST FIPS 204 ML-DSA for every signature that
authenticates a peer where the peer can verify it; FIPS 203 ML-KEM, as
`X25519MLKEM768`, for every TLS key exchange where the peer offers it) with a
classical compatibility chain reserved for the app edge:

- Post-quantum chain: root and issuing CA keys ML-DSA-87; every leaf key
  ML-DSA-65 (ML-DSA-87 accepted for CSRs); every certificate signed with
  ML-DSA-87. Used by every service identity and by every strict hop.
- Compatibility chain: root and issuing CA keys ECDSA P-384
  (`ecdsa-with-SHA384` signatures); leaf keys ECDSA P-256. Used only by the
  app-facing server identities (`gateway-server-compat`,
  `keycloak-server-compat`) and by mobile client certificates enrolled from an
  ECDSA P-256 CSR, i.e. devices whose TLS stack cannot present or verify
  ML-DSA yet. No service identity ever exists on this chain, and the two
  chains never cross-sign each other.
- `keyUsage` is `digitalSignature` only on every leaf.
- CSR intake accepts ML-DSA-65, ML-DSA-87 and ECDSA P-256 (`secp256r1`, named
  curve) keys and rejects RSA, EdDSA, ML-DSA-44 and every other curve
  (`csr_key_rejected`). The chain is selected by key family.
- TLS consumers:
  - strict hops (backend mTLS port, gateway-to-backend egress, JWKS egress,
    `backend-client`): TLS 1.3, `X25519MLKEM768` only, `mldsa65`/`mldsa87`
    only; a classical-only peer never completes a handshake;
  - app-facing listeners (issuer, gateway bootstrap, gateway banking): TLS
    1.3, dual identity selected by the client's signature schemes (ML-DSA
    chain for ML-DSA-only clients, compatibility chain otherwise),
    `X25519MLKEM768` preferred and `X25519` accepted, `mldsa65`/`mldsa87` and
    `ecdsa_secp256r1_sha256`/`ecdsa_secp384r1_sha384` accepted, RSA refused.
- Tooling: OpenSSL >= 3.5 (host or pinned container); no JDK/`keytool`.

## Certificate Profiles

The local v1 mobile client certificate profile is
`quantum-bank-mobile-client-v1`.

The profile is for mobile app instances that have completed OAuth2
authentication and OTK-backed CSR validation.

Required subject and SAN inputs are:

- `oauth2Subject`
- `appInstanceId`
- `deviceId`
- `environment`

The `environment` value separates local, test, and future deployment trust
boundaries. Certificates created for one environment must not be trusted as
client certificates in another environment.

## CSR Intake

The PKI layer accepts CSRs only after backend OTK validation succeeds.

The CSR intake request from backend must include:

- CSR content.
- `oauth2Subject`.
- `appInstanceId`.
- `deviceId`.
- `environment`.
- Certificate profile, initially `quantum-bank-mobile-client-v1`.
- CSR fingerprint computed by backend.
- Backend correlation id.

The PKI layer must reject CSR intake when the certificate profile is unknown,
the environment is unsupported, required identity inputs are missing, or the CSR
cannot satisfy profile policy.

## Issuance

Certificate issuance produces a client certificate usable for gateway mTLS.

The issued certificate must be associated with:

- Profile `quantum-bank-mobile-client-v1`.
- Validated `oauth2Subject`.
- Validated `appInstanceId`.
- Validated `deviceId`.
- Target `environment`.
- Issuance timestamp.
- Expiration timestamp.
- Serial number or equivalent PKI identifier.

The PKI layer returns the issued certificate chain and lifecycle metadata to the
backend. The PKI layer never receives, stores, or reconstructs the mobile private
key.

## Local CA Adapter

Phase 3 selects the D-02 fallback: a PKI-owned local CA adapter inside `pki`.
The adapter uses OpenSSL scripts under `pki/scripts/` and profile material under
`pki/local-ca/` to issue local certificates for
`quantum-bank-mobile-client-v1`.

The local adapter is intentionally owned by PKI. KrakenD consumes trust anchors
and backend invokes the adapter only after OTK and CSR validation. Neither
KrakenD nor backend becomes a certificate authority.

Local public trust material is published under:

- `pki/local-ca/trust/root-ca.crt` and `pki/local-ca/trust/issuing-ca.crt`
  (post-quantum chain)
- `pki/local-ca/trust/root-ca-compat.crt` and
  `pki/local-ca/trust/issuing-ca-compat.crt` (compatibility chain)

Private CA keys, issued private keys, CSRs, serial state, and generated local
secret material are not source-controlled.

## OpenXPKI Swap-In Boundary

OpenXPKI replaces the local CA adapter implementation without changing mobile,
gateway, or backend contracts. The stable adapter request fields are CSR,
`oauth2Subject`, `appInstanceId`, `deviceId`, `environment`,
`certificateProfile`, `csrFingerprint`, and backend correlation id.

## Renewal

Renewal is owned by PKI policy.

For local v1, renewal may be implemented as a new OTK and CSR flow unless a
dedicated renewal endpoint is introduced in a later phase. Renewal must preserve
the same ownership boundary: backend validates application identity and OTK
state, while PKI issues the replacement certificate.

## Renewal Boundary

Dedicated renewal endpoints are out of scope for Phase 3. If local renewal is
needed, it uses a new OAuth2 plus OTK plus CSR bootstrap cycle. This preserves
the same identity and one-use validation path as initial issuance.

Renewal events must be auditable and tied to the previous certificate identifier
when that identifier is available.

## Revocation

Revocation is owned by PKI policy.

Revocation must support invalidating a mobile client certificate by certificate
identifier, `oauth2Subject`, `appInstanceId`, or `deviceId` when local v1 policy
requires it.

The PKI layer must publish revocation state in a form the gateway can enforce in
later phases. Until that enforcement path exists, the contract records the PKI
owner and required data model.

## Revocation Representation

Phase 3 represents local revocation as a plain-text serial denylist at
`pki/local-ca/revoked-serials.txt`. Each non-comment line is one uppercase
hexadecimal certificate serial number.

The local `scripts/revoke-local-cert.sh` command appends serials to this file.
Gateway enforcement of the denylist can mature later, but the PKI-owned
revocation source is present in Phase 3.

## Trust Anchors

The PKI layer owns trust anchors for local development and future deployment
environments.

Trust material must identify:

- Issuing CA.
- Environment.
- Intended gateway consumer.
- Rotation date or replacement policy.
- File or secret location used by local runtime tooling.

Gateway configuration consumes trust anchors from PKI-owned outputs. Trust
anchors are not generated by mobile or backend code.

## Local Trust Material

Local trust anchors are public-only outputs from the local CA adapter. They are
safe to commit when they contain certificates only, never private keys:

- `trust/root-ca.crt`, `trust/issuing-ca.crt` (post-quantum chain)
- `trust/root-ca-compat.crt`, `trust/issuing-ca-compat.crt` (compatibility chain)

These trust anchors are environment-bound to `local` and must not be reused as
test or future deployment trust material.

## OpenXPKI Fallback

OpenXPKI is the fallback implementation if KrakenD cannot satisfy lifecycle
requirements.

The fallback applies when gateway capabilities cover mTLS enforcement but not
certificate issuance, Renewal, Revocation, auditability, or CA lifecycle needs.
The PKI layer may integrate OpenXPKI or another explicitly approved open-source
PKI component in later phases, but this contract names OpenXPKI as the default
fallback candidate for planning and implementation.

## Out of Scope

This contract does not implement a CA.

The following items are out of scope for Phase 1:

- Production CA hardening.
- Hardware-backed key storage.
- Full CRL or OCSP publication.
- Mobile secure enclave integration.
- Automated trust anchor rotation.
- Remote attestation.
- Certificate pinning design.
