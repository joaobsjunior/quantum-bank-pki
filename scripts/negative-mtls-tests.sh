#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"

banking_url="${BANKING_URL:-https://localhost:8443/statements}"
backend_url="${BACKEND_URL:-https://localhost:8080/statements}"
gateway_ca="${GATEWAY_CA_CERT:-${repo_dir}/local-ca/trust/issuing-ca.crt}"
backend_ca="${BACKEND_CA_CERT:-${repo_dir}/local-ca/trust/issuing-ca.crt}"
untrusted_cert="${UNTRUSTED_CLIENT_CERT:-${repo_dir}/local-ca/negative/untrusted-client.crt}"
untrusted_key="${UNTRUSTED_CLIENT_KEY:-${repo_dir}/local-ca/negative/untrusted-client.key}"
expired_cert="${EXPIRED_CLIENT_CERT:-${repo_dir}/local-ca/negative/expired-client.crt}"
expired_key="${EXPIRED_CLIENT_KEY:-${repo_dir}/local-ca/negative/expired-client.key}"
wrong_environment_ca="${WRONG_ENVIRONMENT_CA_CERT:-${repo_dir}/local-ca/negative/wrong-environment-ca.crt}"

tls_failure_pattern="handshake|alert|certificate|required|unknown ca|bad certificate|SSL|tlsv13 alert"

require_running_endpoint() {
  local url="$1"
  local output
  local status

  set +e
  output="$(curl -kfsS --connect-timeout 2 --max-time 4 "${url}" 2>&1)"
  status=$?
  set -e

  if [[ "${status}" -eq 7 || "${status}" -eq 28 ]]; then
    echo "prerequisite failed: service for ${url} is not reachable; start the Phase 3 local runtime first" >&2
    exit 2
  fi
}

expect_tls_failure() {
  local name="$1"
  shift

  local output
  local status
  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e

  if [[ "${status}" -eq 7 || "${status}" -eq 28 ]]; then
    echo "prerequisite failed: ${name} could not reach its target service; start the Phase 3 local runtime first" >&2
    exit 2
  fi

  if [[ "${status}" -eq 0 ]]; then
    echo "negative mTLS case did not fail closed: ${name}" >&2
    exit 1
  fi

  if ! grep -Eiq "${tls_failure_pattern}" <<<"${output}"; then
    echo "negative mTLS case failed for a non-TLS reason: ${name}" >&2
    echo "${output}" >&2
    exit 1
  fi
}

require_running_endpoint "${banking_url}"
require_running_endpoint "${backend_url}"

expect_tls_failure \
  "missing client cert to banking listener" \
  curl -fsS --connect-timeout 2 --max-time 5 --cacert "${gateway_ca}" "${banking_url}"

expect_tls_failure \
  "untrusted client cert to banking listener" \
  curl -fsS --connect-timeout 2 --max-time 5 --cacert "${gateway_ca}" --cert "${untrusted_cert}" --key "${untrusted_key}" "${banking_url}"

expect_tls_failure \
  "expired client cert to banking listener" \
  curl -fsS --connect-timeout 2 --max-time 5 --cacert "${gateway_ca}" --cert "${expired_cert}" --key "${expired_key}" "${banking_url}"

expect_tls_failure \
  "wrong-environment trust anchor to banking listener" \
  curl -fsS --connect-timeout 2 --max-time 5 --cacert "${wrong_environment_ca}" "${banking_url}"

expect_tls_failure \
  "direct backend call without gateway client certificate" \
  curl -fsS --connect-timeout 2 --max-time 5 --cacert "${backend_ca}" "${backend_url}"

echo "negative-mtls-ok"
