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

## Transport Policy (post-quantum first, compatibility chain for the app edge)

The PKI runs two trust chains side by side. The post-quantum chain is used on
every hop where both peers speak ML-DSA; the compatibility chain exists only
for the app-facing listeners and the peers whose TLS stack cannot verify
ML-DSA yet (the Dart/BoringSSL mobile transport and browsers). Both chains
negotiate the `X25519MLKEM768` hybrid key exchange wherever the client offers
it, so the harvest-now-decrypt-later exposure is closed even on the
compatibility path.

| Material | Post-quantum chain | Compatibility chain |
| --- | --- | --- |
| Root CA and issuing CA keys/signatures | **ML-DSA-87** (FIPS 204) | **ECDSA P-384**, `ecdsa-with-SHA384` |
| Server certificates | **ML-DSA-65** keys for every identity (gateway, backend, Keycloak) | **ECDSA P-256** keys for the app-facing identities only (`gateway-server-compat`, `keycloak-server-compat`) |
| Service client certificates (`gateway-client`, `backend-client`) | ML-DSA-65 | none (strict hops never use this chain) |
| `quantum-bank-mobile-client-v1` CSR keys | ML-DSA-65 or ML-DSA-87 | ECDSA P-256 (`secp256r1`) |
| Rejected CSR keys | RSA, EdDSA, ML-DSA-44, every curve but P-256 | same |
| TLS policy on strict hops (backend port, every egress) | TLS 1.3, `X25519MLKEM768` only, `mldsa65:mldsa87` only | not used |
| TLS policy on app-facing listeners (issuer, gateway bootstrap, gateway banking) | dual identity, `X25519MLKEM768` preferred, `mldsa65:mldsa87` | same bind: `X25519` accepted, `ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384` accepted; RSA never |

`sign-csr.sh` picks the chain by the CSR key family and never signs a leaf with
the other family's CA; the two chains never cross-sign each other
(`verify-trust-anchors.sh` proves it).

Every script resolves an OpenSSL **>= 3.5** binary through
`scripts/lib/openssl-pqc.sh`: the host `openssl` when it is new enough,
otherwise the pinned `alpine/openssl:3.5.8` container (Docker required),
otherwise it fails closed. No `keytool`/JDK is needed: PKCS#12 stores are
built with OpenSSL (`-jdktrust anyExtendedKeyUsage` for trust anchors) and
HAProxy terminators consume PEM bundles (`*.pem` = chain + key).

Pre-existing keys of another family found at CA or runtime key paths are moved
aside (`*.pre-pqc.<timestamp>` / `*.replaced.<timestamp>`), never reused.

## Phase 3 Local CA Adapter

Phase 3 uses the PKI-owned local CA adapter fallback while keeping the
OpenXPKI replacement boundary explicit.

Scripts:

- `scripts/bootstrap-local-ca.sh` generates the local root and issuing CA
  material of both chains (`trust/root-ca.crt`, `trust/issuing-ca.crt`,
  `trust/root-ca-compat.crt`, `trust/issuing-ca-compat.crt`) and syncs the
  two root assets of the mobile app.
- `scripts/verify-trust-anchors.sh` verifies public trust anchors.
- `scripts/sign-csr.sh` signs a backend-validated CSR for
  `quantum-bank-mobile-client-v1` under the chain that matches its key family
  and writes the issuing certificate next to the leaf (`<leaf>.issuer`).
- `scripts/revoke-local-cert.sh` records a local certificate serial in
  `local-ca/revoked-serials.txt`.
- `scripts/bootstrap-runtime-certs.sh` generates the ML-DSA-65 runtime
  certificates of every identity, the ECDSA P-256 compatibility certificates of
  the app-facing identities, HAProxy PEM bundles, the union bundles
  (`ca-chain-all.crt`, `trust-anchors.crt`), JVM PKCS#12 stores, the smoke
  enrollment CSRs (one per key family), the ECDSA smoke client and the
  negative fixtures (untrusted, expired, RSA, ML-DSA-44 and untrusted-compat
  client certificates) for the Docker Compose runtime.
- `scripts/verify-runtime-certs.sh` checks every runtime artifact against the
  transport policy, including that no service identity exists on the
  compatibility chain.
- `scripts/negative-mtls-tests.sh` proves missing/untrusted/expired/RSA/
  ML-DSA-44 client certificates fail inside the TLS handshake on the banking
  listener, and that classical-only key exchange or a compatibility-chain
  certificate never reaches the strict backend port.
- `scripts/pqc-handshake-tests.sh` proves, on the issuer, both gateway
  listeners and the backend: TLS 1.3 + `X25519MLKEM768` + `mldsa65` for
  post-quantum clients; the ECDSA P-256 identity (with the hybrid group when
  offered, X25519 otherwise) for compatibility clients on the app-facing
  listeners; RSA refused everywhere; classical schemes, classical groups and
  ECDSA identities refused on the backend.

Public trust anchors live in `local-ca/trust/`. Private CA keys and generated
certificate material stay in ignored directories.

## Testing & CI

- Validate PKI locally: `./scripts/ci-validate.sh` bootstraps both local CA
  chains, verifies the trust anchors, generates the runtime material and
  verifies the transport policy on every artifact.
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
