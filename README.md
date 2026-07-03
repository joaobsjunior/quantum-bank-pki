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
- `scripts/bootstrap-runtime-certs.sh` generates local server/client runtime
  certificates and backend PKCS12 stores for the Phase 6 Docker Compose runtime.

Public trust anchors live in `local-ca/trust/`. Private CA keys and generated
certificate material stay in ignored directories.

## Testing & CI

- Validate PKI locally: `./scripts/ci-validate.sh` bootstraps the local CA and
  runs `scripts/verify-trust-anchors.sh`.
- Negative mTLS tests (`scripts/negative-mtls-tests.sh`) require a running
  runtime and run in the superproject's opt-in `e2e` job, not the static gate.
- CI (`.github/workflows/ci.yml`) runs the validation gate on every push/PR to
  `main`.

## Runtime Requirements

PKI is script-based (Bash + OpenSSL) and is **not** a Compose service — its
`local-ca/` material is mounted into the backend and gateway containers.

| Resource | Footprint |
| --- | --- |
| Memory | negligible (short-lived OpenSSL processes) |
| CPU | negligible (brief spikes during key generation / CSR signing) |
| Storage | a few MB under `local-ca/` (CA keys, issued certs, runtime PKCS12 stores) |

- Requires `openssl` on the host (or runs inside the mounted container context).
- Private keys and generated certs stay in ignored directories; only public
  trust anchors under `local-ca/trust/` are tracked.
