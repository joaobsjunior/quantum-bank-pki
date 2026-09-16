#!/bin/sh
# POSIX sh so it also runs inside the curl-only Compose service.
set -eu

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"

banking_url="${BANKING_URL:-https://localhost:8443/statements}"
bootstrap_url="${BOOTSTRAP_URL:-https://localhost:8080/auth/otk}"
backend_url="${BACKEND_URL:-https://backend:8080/statements}"
gateway_ca="${GATEWAY_CA_CERT:-${repo_dir}/local-ca/trust/root-ca.crt}"
backend_ca="${BACKEND_CA_CERT:-${repo_dir}/local-ca/trust/root-ca.crt}"
untrusted_cert="${UNTRUSTED_CLIENT_CERT:-${repo_dir}/local-ca/negative/untrusted-client.crt}"
untrusted_key="${UNTRUSTED_CLIENT_KEY:-${repo_dir}/local-ca/negative/untrusted-client.key}"
expired_cert="${EXPIRED_CLIENT_CERT:-${repo_dir}/local-ca/negative/expired-client.crt}"
expired_key="${EXPIRED_CLIENT_KEY:-${repo_dir}/local-ca/negative/expired-client.key}"
classical_cert="${CLASSICAL_CLIENT_CERT:-${repo_dir}/local-ca/negative/classical-client.crt}"
classical_key="${CLASSICAL_CLIENT_KEY:-${repo_dir}/local-ca/negative/classical-client.key}"
mldsa44_cert="${MLDSA44_CLIENT_CERT:-${repo_dir}/local-ca/negative/mldsa44-client.crt}"
mldsa44_key="${MLDSA44_CLIENT_KEY:-${repo_dir}/local-ca/negative/mldsa44-client.key}"
wrong_environment_ca="${WRONG_ENVIRONMENT_CA_CERT:-${repo_dir}/local-ca/negative/wrong-environment-ca.crt}"
valid_cert="${MOBILE_CLIENT_CERT:-${repo_dir}/local-ca/runtime/mobile-smoke-client.crt}"
valid_key="${MOBILE_CLIENT_KEY:-${repo_dir}/local-ca/runtime/mobile-smoke-client.key}"

# The negative fixtures must exist before any case runs. A missing certificate
# file makes curl fail with a message that could look like a TLS failure, so
# without this guard every case below could pass vacuously.
for fixture in "${gateway_ca}" "${backend_ca}" "${untrusted_cert}" "${untrusted_key}" \
  "${expired_cert}" "${expired_key}" "${classical_cert}" "${classical_key}" \
  "${mldsa44_cert}" "${mldsa44_key}" "${wrong_environment_ca}" "${valid_cert}" "${valid_key}"; do
  if [ ! -f "${fixture}" ]; then
    echo "missing negative mTLS fixture: ${fixture}; run scripts/bootstrap-runtime-certs.sh first" >&2
    exit 2
  fi
done

require_running_endpoint() {
  url="$1"
  set +e
  curl -kfsS --connect-timeout 2 --max-time 4 "${url}" >/dev/null 2>&1
  status=$?
  set -e
  if [ "${status}" -eq 7 ] || [ "${status}" -eq 28 ] || [ "${status}" -eq 6 ]; then
    echo "prerequisite failed: service for ${url} is not reachable; start the local runtime first" >&2
    exit 2
  fi
}

# Only a TLS-layer rejection counts as a pass. Local file problems, DNS
# failures, timeouts, and HTTP-level errors (for example a 401) all fail.
expect_tls_failure() {
  name="$1"
  shift

  set +e
  output="$(curl -fsS --connect-timeout 2 --max-time 5 "$@" 2>&1)"
  status=$?
  set -e

  if [ "${status}" -eq 7 ] || [ "${status}" -eq 28 ] || [ "${status}" -eq 6 ]; then
    echo "prerequisite failed: ${name} could not reach its target service; start the local runtime first" >&2
    exit 2
  fi

  if [ "${status}" -eq 0 ]; then
    echo "negative mTLS case did not fail closed: ${name}" >&2
    exit 1
  fi

  case "${output}" in
    *"could not load"*|*"returned error: "*)
      echo "negative mTLS case failed for a non-TLS reason: ${name}" >&2
      echo "${output}" >&2
      exit 1
      ;;
    *handshake*|*alert*|*"certificate required"*|*"certificate verify"*|*"certificate has expired"*|*"unknown ca"*|*"bad certificate"*|*"SSL routines"*|*"OpenSSL SSL_"*|*"SSL certificate problem"*|*"TLS connect error"*)
      return 0
      ;;
    *"Send failure: Broken pipe"*)
      # The terminator aborted the handshake while curl was still writing the
      # (large, post-quantum) Certificate message; the peer's alert is lost to
      # the reset but the rejection happened inside TLS, before any HTTP byte.
      return 0
      ;;
    *)
      echo "negative mTLS case failed for a non-TLS reason: ${name}" >&2
      echo "${output}" >&2
      exit 1
      ;;
  esac
}

require_running_endpoint "${banking_url}"
require_running_endpoint "${bootstrap_url}"
require_running_endpoint "${backend_url}"

expect_tls_failure \
  "missing client cert to banking listener" \
  --cacert "${gateway_ca}" "${banking_url}"

expect_tls_failure \
  "untrusted client cert to banking listener" \
  --cacert "${gateway_ca}" --cert "${untrusted_cert}" --key "${untrusted_key}" "${banking_url}"

expect_tls_failure \
  "expired client cert to banking listener" \
  --cacert "${gateway_ca}" --cert "${expired_cert}" --key "${expired_key}" "${banking_url}"

expect_tls_failure \
  "wrong-environment trust anchor to banking listener" \
  --cacert "${wrong_environment_ca}" "${banking_url}"

# Post-quantum policy at the TLS layer: a certificate the real CA signed for a
# classical RSA key, or for the lower ML-DSA-44 category, cannot authenticate
# because the listeners only accept mldsa65/mldsa87 client signature schemes.
expect_tls_failure \
  "classical RSA client cert (signed by the real CA) to banking listener" \
  --cacert "${gateway_ca}" --cert "${classical_cert}" --key "${classical_key}" "${banking_url}"

expect_tls_failure \
  "ML-DSA-44 client cert (signed by the real CA) to banking listener" \
  --cacert "${gateway_ca}" --cert "${mldsa44_cert}" --key "${mldsa44_key}" "${banking_url}"

# Post-quantum key exchange is mandatory on every listener: a client that only
# offers classical groups never completes a handshake, even with valid
# credentials.
expect_tls_failure \
  "classical-only key exchange (X25519) to banking listener" \
  --cacert "${gateway_ca}" --cert "${valid_cert}" --key "${valid_key}" --curves X25519 "${banking_url}"

expect_tls_failure \
  "classical-only key exchange (X25519) to bootstrap listener" \
  --cacert "${gateway_ca}" --curves X25519 "${bootstrap_url}"

expect_tls_failure \
  "classical-only key exchange (secp256r1) to backend mTLS port" \
  --cacert "${backend_ca}" --curves prime256v1 "${backend_url}"

expect_tls_failure \
  "direct backend call without gateway client certificate" \
  --cacert "${backend_ca}" "${backend_url}"

expect_tls_failure \
  "direct backend call with untrusted client certificate" \
  --cacert "${backend_ca}" --cert "${untrusted_cert}" --key "${untrusted_key}" "${backend_url}"

expect_tls_failure \
  "direct backend call with classical RSA client certificate" \
  --cacert "${backend_ca}" --cert "${classical_cert}" --key "${classical_key}" "${backend_url}"

echo "negative-mtls-ok"
