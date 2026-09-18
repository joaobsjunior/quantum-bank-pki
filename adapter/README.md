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

The command verifies the proof of possession, accepts ML-DSA-65, ML-DSA-87
(post-quantum chain) or ECDSA P-256 (compatibility chain) subject keys, issues
the certificate under the chain that matches the key family (ML-DSA-87 or
`ecdsa-with-SHA384` signature) and writes that chain's issuing certificate to
`<output>.issuer` so the backend returns a homogeneous chain; it needs
OpenSSL >= 3.5 (the backend runtime image ships it).

The shell command accepts file paths and identity values directly. The backend
adapter remains shaped like an RPC request so OpenXPKI can replace this local
command without changing mobile, gateway, or backend contracts.

## OpenXPKI Swap-In

OpenXPKI will replace only the implementation behind this boundary. The request
fields, certificate profile, local environment binding, and PKI ownership rules
remain stable.

