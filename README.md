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

Public trust anchors live in `local-ca/trust/`. Private CA keys and generated
certificate material stay in ignored directories.
