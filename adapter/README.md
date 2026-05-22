# PKI Adapter Boundary

The Phase 3 PKI adapter is a local CA command boundary owned by `pki`.
Backend code validates OTK and CSR inputs before invoking this boundary; it does
not issue, renew, revoke, or approve certificates.

## Local Command

`scripts/sign-csr.sh` accepts these fields:

- CSR path containing the backend-validated certificate signing request.
- Output certificate path.
- `oauth2Subject`
- `appInstanceId`
- `deviceId`
- `environment`
- `certificateProfile`, fixed to `quantum-bank-mobile-client-v1`.
- `csrFingerprint`, supplied by backend in the higher-level adapter contract.
- Correlation id, supplied by backend in the higher-level adapter contract.

The shell command accepts file paths and identity values directly. The backend
adapter remains shaped like an RPC request so OpenXPKI can replace this local
command without changing mobile, gateway, or backend contracts.

## OpenXPKI Swap-In

OpenXPKI will replace only the implementation behind this boundary. The request
fields, certificate profile, local environment binding, and PKI ownership rules
remain stable.

