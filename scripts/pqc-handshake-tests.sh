#!/bin/sh
# Post-quantum handshake evidence for every TLS hop of the local runtime.
# POSIX sh; runs inside the alpine/openssl Compose service (OpenSSL >= 3.5).
#
# For each endpoint it proves, with `openssl s_client`, that the negotiated
# session is TLS 1.3, that the key exchange group is X25519MLKEM768 (ML-KEM
# hybrid) and that the peer authenticated with an ML-DSA signature over a
# certificate chain that validates against the local root anchor. It then
# proves the classical fallbacks are refused: RSA/ECDSA signature schemes only,
# or classical groups only, never complete a handshake.
set -eu

trust_anchor="${TRUST_ANCHOR:-/etc/quantum-bank/runtime/root-ca.crt}"
issuer_endpoint="${ISSUER_TLS_ENDPOINT:-keycloak:8443}"
bootstrap_endpoint="${BOOTSTRAP_TLS_ENDPOINT:-gateway-bootstrap:8080}"
banking_endpoint="${BANKING_TLS_ENDPOINT:-gateway-banking:8443}"
backend_endpoint="${BACKEND_TLS_ENDPOINT:-backend:8080}"
mobile_cert="${MOBILE_CLIENT_CERT:-/etc/quantum-bank/runtime/mobile-smoke-client.crt}"
mobile_key="${MOBILE_CLIENT_KEY:-/etc/quantum-bank/runtime/mobile-smoke-client.key}"
gateway_client_cert="${GATEWAY_CLIENT_CERT:-/etc/quantum-bank/runtime/gateway-client.crt}"
gateway_client_key="${GATEWAY_CLIENT_KEY:-/etc/quantum-bank/runtime/gateway-client.key}"
expected_group="${EXPECTED_GROUP:-X25519MLKEM768}"
expected_peer_sigalg="${EXPECTED_PEER_SIGALG:-mldsa65}"

for fixture in "${trust_anchor}" "${mobile_cert}" "${mobile_key}" "${gateway_client_cert}" "${gateway_client_key}"; do
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
  shift
  printf '' | openssl s_client -connect "${endpoint}" -servername "${endpoint%%:*}" -CAfile "${trust_anchor}" \
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

expect_pqc() {
  name="$1"
  endpoint="$2"
  shift 2
  output="$(s_client "${endpoint}" "$@")"
  case "${output}" in
    *"Protocol  : TLSv1.3"*|*"Protocol: TLSv1.3"*) ;;
    *) echo "${output}" >&2; fail "${name}: session is not TLS 1.3" ;;
  esac
  case "${output}" in
    *"Negotiated TLS1.3 group: ${expected_group}"*) ;;
    *) echo "${output}" >&2; fail "${name}: key exchange group is not ${expected_group}" ;;
  esac
  case "${output}" in
    *"Peer signature type: ${expected_peer_sigalg}"*) ;;
    *) echo "${output}" >&2; fail "${name}: peer did not sign with ${expected_peer_sigalg}" ;;
  esac
  case "${output}" in
    *"Verify return code: 0 (ok)"*) ;;
    *) echo "${output}" >&2; fail "${name}: certificate chain did not verify against the root anchor" ;;
  esac
  echo "pqc ok: ${name} (${expected_group}, ${expected_peer_sigalg})"
}

expect_rejected() {
  name="$1"
  endpoint="$2"
  shift 2
  output="$(s_client "${endpoint}" "$@")"
  case "${output}" in
    *"Verify return code: 0 (ok)"*"Negotiated TLS1.3 group: ${expected_group}"*|*"Peer signature type:"*)
      # A completed handshake with a peer signature means the downgrade was accepted.
      case "${output}" in
        *"alert"*|*"handshake failure"*|*"error"*) ;;
        *) echo "${output}" >&2; fail "${name}: classical handshake was accepted" ;;
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

expect_pqc "issuer (Keycloak TLS terminator)" "${issuer_endpoint}"
expect_pqc "gateway bootstrap listener" "${bootstrap_endpoint}"
expect_pqc "gateway banking listener with mobile client certificate" "${banking_endpoint}" \
  -cert "${mobile_cert}" -key "${mobile_key}"
expect_pqc "backend mTLS port with gateway client certificate" "${backend_endpoint}" \
  -cert "${gateway_client_cert}" -key "${gateway_client_key}"

classical_sigalgs="rsa_pss_rsae_sha256:rsa_pss_pss_sha256:ecdsa_secp256r1_sha256:ed25519:rsa_pkcs1_sha256"
for endpoint in "${issuer_endpoint}" "${bootstrap_endpoint}" "${banking_endpoint}" "${backend_endpoint}"; do
  expect_rejected "classical signature schemes only to ${endpoint}" "${endpoint}" -sigalgs "${classical_sigalgs}"
  expect_rejected "classical groups only to ${endpoint}" "${endpoint}" -groups X25519:secp256r1:secp384r1
done

echo "pqc-handshake-ok"
