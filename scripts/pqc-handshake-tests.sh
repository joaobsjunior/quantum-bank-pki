#!/bin/sh
# Transport policy evidence for every TLS hop of the local runtime.
# POSIX sh; runs inside the alpine/openssl Compose service (OpenSSL >= 3.5).
#
# Two listener classes exist:
#
#   * strict hops (backend mTLS port, and every service-to-service egress):
#     TLS 1.3, X25519MLKEM768 only, ML-DSA signature schemes only. A client
#     that offers classical signature schemes only, or classical groups only,
#     never completes a handshake.
#   * app-facing listeners (issuer, gateway bootstrap, gateway banking):
#     TLS 1.3, X25519MLKEM768 preferred with X25519 accepted, and a dual
#     identity: the ML-DSA-65 certificate for peers that only offer ML-DSA
#     schemes, the ECDSA P-256 compatibility certificate for peers whose TLS
#     stack cannot verify ML-DSA yet (Dart/BoringSSL, browsers). RSA schemes
#     are refused everywhere.
#
# For each endpoint it proves, with `openssl s_client`, the negotiated
# protocol, key exchange group and peer signature scheme, and that the peer
# chain validates against the expected root anchor.
set -eu

trust_anchor="${TRUST_ANCHOR:-/etc/quantum-bank/runtime/root-ca.crt}"
compat_trust_anchor="${COMPAT_TRUST_ANCHOR:-/etc/quantum-bank/runtime/root-ca-compat.crt}"
issuer_endpoint="${ISSUER_TLS_ENDPOINT:-keycloak:8443}"
bootstrap_endpoint="${BOOTSTRAP_TLS_ENDPOINT:-gateway-bootstrap:8080}"
banking_endpoint="${BANKING_TLS_ENDPOINT:-gateway-banking:8443}"
backend_endpoint="${BACKEND_TLS_ENDPOINT:-backend:8080}"
mobile_cert="${MOBILE_CLIENT_CERT:-/etc/quantum-bank/runtime/mobile-smoke-client.crt}"
mobile_key="${MOBILE_CLIENT_KEY:-/etc/quantum-bank/runtime/mobile-smoke-client.key}"
compat_mobile_cert="${COMPAT_MOBILE_CLIENT_CERT:-/etc/quantum-bank/runtime/mobile-smoke-client-compat.crt}"
compat_mobile_key="${COMPAT_MOBILE_CLIENT_KEY:-/etc/quantum-bank/runtime/mobile-smoke-client-compat.key}"
gateway_client_cert="${GATEWAY_CLIENT_CERT:-/etc/quantum-bank/runtime/gateway-client.crt}"
gateway_client_key="${GATEWAY_CLIENT_KEY:-/etc/quantum-bank/runtime/gateway-client.key}"
expected_group="${EXPECTED_GROUP:-X25519MLKEM768}"
expected_peer_sigalg="${EXPECTED_PEER_SIGALG:-mldsa65}"
compat_group="${COMPAT_GROUP:-X25519}"
compat_peer_sigalg="${COMPAT_PEER_SIGALG:-ecdsa_secp256r1_sha256}"
pqc_sigalgs="mldsa65:mldsa87"
compat_sigalgs="ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384"
classical_sigalgs="rsa_pss_rsae_sha256:rsa_pss_pss_sha256:rsa_pkcs1_sha256"

for fixture in "${trust_anchor}" "${compat_trust_anchor}" "${mobile_cert}" "${mobile_key}" \
  "${compat_mobile_cert}" "${compat_mobile_key}" "${gateway_client_cert}" "${gateway_client_key}"; do
  if [ ! -f "${fixture}" ]; then
    echo "missing fixture ${fixture}; run pki/scripts/bootstrap-runtime-certs.sh first" >&2
    exit 2
  fi
done

fail() {
  echo "pqc handshake test failed: $*" >&2
  exit 1
}

s_client() {
  # stdin closed immediately so the session is only used for the handshake.
  endpoint="$1"
  anchor="$2"
  shift 2
  printf '' | openssl s_client -connect "${endpoint}" -servername "${endpoint%%:*}" -CAfile "${anchor}" \
    -verify_return_error -tls1_3 "$@" 2>&1 || true
}

wait_for_endpoint() {
  endpoint="$1"
  attempts=0
  while [ "${attempts}" -lt 60 ]; do
    attempts=$((attempts + 1))
    if printf '' | openssl s_client -connect "${endpoint}" -servername "${endpoint%%:*}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  fail "endpoint ${endpoint} is not reachable"
}

# expect_session NAME ENDPOINT ANCHOR GROUP PEER_SIGALG [s_client options...]
expect_session() {
  name="$1"
  endpoint="$2"
  anchor="$3"
  group="$4"
  sigalg="$5"
  shift 5
  output="$(s_client "${endpoint}" "${anchor}" "$@")"
  case "${output}" in
    *"Protocol  : TLSv1.3"*|*"Protocol: TLSv1.3"*) ;;
    *) echo "${output}" >&2; fail "${name}: session is not TLS 1.3" ;;
  esac
  # OpenSSL prints the hybrid/KEM group on its own line and a classical
  # (EC)DH group as the server temp key; a classical session must not carry
  # the hybrid line either.
  case "${group}" in
    *MLKEM*)
      case "${output}" in
        *"Negotiated TLS1.3 group: ${group}
"*) ;;
        *) echo "${output}" >&2; fail "${name}: key exchange group is not ${group}" ;;
      esac
      ;;
    *)
      case "${output}" in
        *"Negotiated TLS1.3 group: "*MLKEM*) echo "${output}" >&2; fail "${name}: expected the classical group ${group}, got a hybrid group" ;;
      esac
      case "${output}" in
        *"Peer Temp Key: ${group},"*|*"Server Temp Key: ${group},"*) ;;
        *) echo "${output}" >&2; fail "${name}: key exchange group is not ${group}" ;;
      esac
      ;;
  esac
  case "${output}" in
    *"Peer signature type: ${sigalg}
"*) ;;
    *) echo "${output}" >&2; fail "${name}: peer did not sign with ${sigalg}" ;;
  esac
  case "${output}" in
    *"Verify return code: 0 (ok)"*) ;;
    *) echo "${output}" >&2; fail "${name}: certificate chain did not verify against the expected root anchor" ;;
  esac
  echo "pqc ok: ${name} (${group}, ${sigalg})"
}

expect_rejected() {
  name="$1"
  endpoint="$2"
  shift 2
  output="$(s_client "${endpoint}" "${trust_anchor}" "$@")"
  case "${output}" in
    *"Peer signature type:"*)
      case "${output}" in
        *"alert"*|*"handshake failure"*|*"error:"*) ;;
        *) echo "${output}" >&2; fail "${name}: handshake was accepted" ;;
      esac
      ;;
  esac
  case "${output}" in
    *"alert"*|*"handshake failure"*|*"error:"*) echo "pqc ok: ${name} rejected" ;;
    *) echo "${output}" >&2; fail "${name}: expected a TLS failure" ;;
  esac
}

wait_for_endpoint "${issuer_endpoint}"
wait_for_endpoint "${bootstrap_endpoint}"
wait_for_endpoint "${banking_endpoint}"
wait_for_endpoint "${backend_endpoint}"

# 1. Post-quantum clients (BCJSSE services, PQ-capable apps) get the ML-DSA
#    identity and the hybrid group on every listener.
expect_session "issuer, PQ client" "${issuer_endpoint}" "${trust_anchor}" \
  "${expected_group}" "${expected_peer_sigalg}" -sigalgs "${pqc_sigalgs}"
expect_session "gateway bootstrap, PQ client" "${bootstrap_endpoint}" "${trust_anchor}" \
  "${expected_group}" "${expected_peer_sigalg}" -sigalgs "${pqc_sigalgs}"
expect_session "gateway banking, PQ client with ML-DSA-65 client certificate" "${banking_endpoint}" "${trust_anchor}" \
  "${expected_group}" "${expected_peer_sigalg}" -sigalgs "${pqc_sigalgs}" -cert "${mobile_cert}" -key "${mobile_key}"
expect_session "backend mTLS port, gateway client certificate" "${backend_endpoint}" "${trust_anchor}" \
  "${expected_group}" "${expected_peer_sigalg}" -cert "${gateway_client_cert}" -key "${gateway_client_key}"

# 2. Compatibility clients (Dart/BoringSSL mobile transport, browsers):
#    ECDSA identity from the compatibility chain. With the hybrid group when
#    the client offers it, with X25519 when it does not.
expect_session "issuer, compat client with hybrid group" "${issuer_endpoint}" "${compat_trust_anchor}" \
  "${expected_group}" "${compat_peer_sigalg}" -sigalgs "${compat_sigalgs}"
expect_session "issuer, compat client with classical group" "${issuer_endpoint}" "${compat_trust_anchor}" \
  "${compat_group}" "${compat_peer_sigalg}" -sigalgs "${compat_sigalgs}" -groups "${compat_group}"
expect_session "gateway bootstrap, compat client with hybrid group" "${bootstrap_endpoint}" "${compat_trust_anchor}" \
  "${expected_group}" "${compat_peer_sigalg}" -sigalgs "${compat_sigalgs}"
expect_session "gateway bootstrap, compat client with classical group" "${bootstrap_endpoint}" "${compat_trust_anchor}" \
  "${compat_group}" "${compat_peer_sigalg}" -sigalgs "${compat_sigalgs}" -groups "${compat_group}"
expect_session "gateway banking, compat client with ECDSA P-256 client certificate" "${banking_endpoint}" "${compat_trust_anchor}" \
  "${expected_group}" "${compat_peer_sigalg}" -sigalgs "${compat_sigalgs}" -cert "${compat_mobile_cert}" -key "${compat_mobile_key}"
expect_session "gateway banking, compat client with classical group" "${banking_endpoint}" "${compat_trust_anchor}" \
  "${compat_group}" "${compat_peer_sigalg}" -sigalgs "${compat_sigalgs}" -groups "${compat_group}" -cert "${compat_mobile_cert}" -key "${compat_mobile_key}"

# 3. Fail closed: RSA schemes nowhere; classical-only clients never reach the
#    strict backend hop; an ML-DSA-only client cannot authenticate with an
#    ECDSA certificate and vice versa.
for endpoint in "${issuer_endpoint}" "${bootstrap_endpoint}" "${banking_endpoint}" "${backend_endpoint}"; do
  expect_rejected "RSA signature schemes only to ${endpoint}" "${endpoint}" -sigalgs "${classical_sigalgs}"
done
expect_rejected "classical signature schemes only to ${backend_endpoint}" "${backend_endpoint}" -sigalgs "${compat_sigalgs}:${classical_sigalgs}"
expect_rejected "classical groups only to ${backend_endpoint}" "${backend_endpoint}" -groups X25519:secp256r1:secp384r1
expect_rejected "ECDSA client certificate to ${backend_endpoint}" "${backend_endpoint}" -cert "${compat_mobile_cert}" -key "${compat_mobile_key}"
expect_rejected "ECDSA client certificate with PQ-only schemes to ${banking_endpoint}" "${banking_endpoint}" -sigalgs "${pqc_sigalgs}" -cert "${compat_mobile_cert}" -key "${compat_mobile_key}"
expect_rejected "ML-DSA client certificate with compat-only schemes to ${banking_endpoint}" "${banking_endpoint}" -sigalgs "${compat_sigalgs}" -cert "${mobile_cert}" -key "${mobile_key}"

echo "pqc-handshake-ok"
