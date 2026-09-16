# Quantum Bank PKI

PKI assets and integration layer for runtime certificate provisioning.

Initial responsibilities:

- OTK-driven certificate bootstrap flow
- CSR intake and certificate issuance integration
- Open source PKI evaluation and implementation, such as OpenXPKI if KrakenD does not cover the required lifecycle
- mTLS trust material for local development and deployment environments

## Phase 1 Contract Ownership

The PKI layer owns this Phase 1 contract:

- [Certificate Lifecycle Contract](docs/contracts/certificate-lifecycle.md) for CONT-01 certificate profiles, CSR intake, issuance, renewal, revocation, trust anchors, and OpenXPKI fallback.

Later PKI implementation must provide trust material consumed by KrakenD while keeping certificate lifecycle ownership outside the gateway.

## Post-Quantum Policy (ML-DSA only)

The PKI is post-quantum only, end to end:

| Material | Algorithm |
| --- | --- |
| Root CA and issuing CA keys/signatures | **ML-DSA-87** (FIPS 204) |
| Runtime server/client certificates (gateway, backend, Keycloak, backend-client, smoke client) | **ML-DSA-65** keys, ML-DSA-87 signatures |
| `quantum-bank-mobile-client-v1` CSR keys | **ML-DSA-65** or ML-DSA-87; RSA, EC, EdDSA and ML-DSA-44 are rejected |
| TLS policy every consumer enforces | TLS 1.3, `X25519MLKEM768` (ML-KEM hybrid), `mldsa65:mldsa87` signature schemes |

Every script resolves an OpenSSL **>= 3.5** binary through
`scripts/lib/openssl-pqc.sh`: the host `openssl` when it is new enough,
otherwise the pinned `alpine/openssl:3.5.8` container (Docker required),
otherwise it fails closed. No `keytool`/JDK is needed: PKCS#12 stores are
built with OpenSSL (`-jdktrust anyExtendedKeyUsage` for trust anchors) and
HAProxy terminators consume PEM bundles (`*.pem` = chain + key).

Pre-existing classical keys found at CA or runtime key paths are moved aside
(`*.pre-pqc.<timestamp>`), never reused.

## Phase 3 Local CA Adapter

Phase 3 uses the PKI-owned local CA adapter fallback while keeping the
OpenXPKI replacement boundary explicit.

Scripts:

- `scripts/bootstrap-local-ca.sh` generates local root and issuing CA material.
- `scripts/verify-trust-anchors.sh` verifies public trust anchors.
- `scripts/sign-csr.sh` signs a backend-validated CSR for
  `quantum-bank-mobile-client-v1`.
- `scripts/revoke-local-cert.sh` records a local certificate serial in
  `local-ca/revoked-serials.txt`.
- `scripts/bootstrap-runtime-certs.sh` generates local ML-DSA-65 server/client
  runtime certificates, HAProxy PEM bundles, JVM PKCS#12 stores, the smoke
  enrollment CSR and the negative fixtures (untrusted, expired, RSA and
  ML-DSA-44 client certificates) for the Docker Compose runtime.
- `scripts/verify-runtime-certs.sh` checks every runtime artifact against the
  post-quantum policy.
- `scripts/negative-mtls-tests.sh` proves missing/untrusted/expired/classical
  client certificates and classical-only key exchange fail inside the TLS
  handshake on every listener.
- `scripts/pqc-handshake-tests.sh` proves TLS 1.3 + `X25519MLKEM768` + ML-DSA
  peer signatures on the issuer, both gateway listeners and the backend, and
  that classical-only clients are refused.

Public trust anchors live in `local-ca/trust/`. Private CA keys and generated
certificate material stay in ignored directories.

## Testing & CI

- Validate PKI locally: `./scripts/ci-validate.sh` bootstraps the ML-DSA-87
  local CA, verifies the trust anchors, generates the runtime material and
  verifies the post-quantum policy on every artifact.
- Negative mTLS tests and PQC handshake tests require a running runtime and run
  in the superproject's opt-in `e2e` job, not the static gate.
- CI (`.github/workflows/ci.yml`) runs the validation gate on every push/PR to
  `main`.

## Runtime Requirements

PKI is **not** a running service — it is a set of Bash + OpenSSL scripts, and its
`local-ca/` folder is mounted into the backend and gateway containers.

### Recommended configuration

**Nothing to provision.** It only needs:

| Requirement | Recommended |
| --- | --- |
| Tooling | **OpenSSL >= 3.5** on the host, or **Docker** (pinned `alpine/openssl:3.5.8`) |
| Memory / CPU | negligible (only brief spikes during key generation / CSR signing) |
| Disk | **a few MB** under `local-ca/` (CA keys, issued certs, PKCS12 stores) |

### Good to know

- Private keys and issued certs live in ignored folders; only the public trust
  anchors under `local-ca/trust/` are tracked.
