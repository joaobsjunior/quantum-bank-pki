#!/usr/bin/env bash
set -euo pipefail

# Verifies that every runtime artifact produced by bootstrap-runtime-certs.sh
# honours the post-quantum policy: ML-DSA-65 leaf keys, ML-DSA-87 signatures,
# chains that validate against the root anchor, OpenSSL-built PKCS#12 stores
# and the negative fixtures with their intended (forbidden) algorithms.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=lib/openssl-pqc.sh
source "${script_dir}/lib/openssl-pqc.sh"
pqc_init "${repo_dir}"

ca_dir="${repo_dir}/local-ca"
runtime_dir="${ca_dir}/runtime"
negative_dir="${ca_dir}/negative"
root_cert="${ca_dir}/trust/root-ca.crt"
issuing_cert="${ca_dir}/trust/issuing-ca.crt"
password="${QUANTUM_BANK_RUNTIME_KEYSTORE_PASSWORD:-changeit}"
leaf_algorithm="${QUANTUM_BANK_PQC_LEAF_ALGORITHM}"
ca_algorithm="${QUANTUM_BANK_PQC_CA_ALGORITHM}"

require_file() {
  if [[ ! -f "$1" ]]; then
    echo "missing $1; run scripts/bootstrap-runtime-certs.sh first" >&2
    exit 1
  fi
}

for leaf in gateway-server backend-server gateway-client mobile-smoke-client backend-client keycloak-server; do
  for suffix in crt key pem; do
    require_file "${runtime_dir}/${leaf}.${suffix}"
  done
  pqc_require_algorithm x509 "${runtime_dir}/${leaf}.crt" "${leaf_algorithm}"
  pqc_require_algorithm key "${runtime_dir}/${leaf}.key" "${leaf_algorithm}"
  pqc_require_signature_algorithm "${runtime_dir}/${leaf}.crt" "${ca_algorithm}"
  pqc_openssl verify -CAfile "${root_cert}" -untrusted "${issuing_cert}" "${runtime_dir}/${leaf}.crt" >/dev/null
  if ! pqc_openssl x509 -in "${runtime_dir}/${leaf}.crt" -noout -ext keyUsage | grep -q "Digital Signature"; then
    echo "${leaf}.crt must carry the digitalSignature key usage" >&2
    exit 1
  fi
  if pqc_openssl x509 -in "${runtime_dir}/${leaf}.crt" -noout -ext keyUsage | grep -q "Key Encipherment"; then
    echo "${leaf}.crt must not advertise keyEncipherment (RSA-only usage)" >&2
    exit 1
  fi
done

for store in backend-server backend-client; do
  require_file "${runtime_dir}/${store}.p12"
  key_pem="$(pqc_openssl pkcs12 -in "${runtime_dir}/${store}.p12" -passin "pass:${password}" -nocerts -nodes 2>/dev/null)"
  key_file="${ca_dir}/tmp/verify-${store}.key"
  mkdir -p "${ca_dir}/tmp"
  printf '%s\n' "${key_pem}" > "${key_file}"
  chmod 600 "${key_file}"
  store_algorithm="$(pqc_public_key_algorithm key "${key_file}" || true)"
  rm -f "${key_file}"
  if [[ "${store_algorithm}" != "${leaf_algorithm}" ]]; then
    echo "${store}.p12 does not carry an ${leaf_algorithm} private key (found '${store_algorithm:-none}')" >&2
    exit 1
  fi
done

for store in backend-truststore backend-client-truststore; do
  require_file "${runtime_dir}/${store}.p12"
  bags="$(pqc_openssl pkcs12 -in "${runtime_dir}/${store}.p12" -passin "pass:${password}" -nokeys 2>/dev/null)"
  anchors="$(printf '%s\n' "${bags}" | grep -c 'BEGIN CERTIFICATE' || true)"
  if [[ "${anchors}" != "2" ]]; then
    echo "${store}.p12 must contain exactly the root and issuing anchors, found ${anchors}" >&2
    exit 1
  fi
  trusted="$(printf '%s\n' "${bags}" | grep -c 'Trusted key usage (Oracle)' || true)"
  if [[ "${trusted}" != "2" ]]; then
    echo "${store}.p12 anchors are missing the JDK trusted-usage attribute (-jdktrust), found ${trusted}" >&2
    exit 1
  fi
done

require_file "${runtime_dir}/mobile-smoke-enroll.csr"
pqc_require_algorithm req "${runtime_dir}/mobile-smoke-enroll.csr" "${leaf_algorithm}"
pqc_openssl req -in "${runtime_dir}/mobile-smoke-enroll.csr" -noout -verify >/dev/null 2>&1

require_file "${negative_dir}/untrusted-client.crt"
pqc_require_algorithm x509 "${negative_dir}/untrusted-client.crt" "${leaf_algorithm}"
if pqc_openssl verify -CAfile "${root_cert}" -untrusted "${issuing_cert}" "${negative_dir}/untrusted-client.crt" >/dev/null 2>&1; then
  echo "untrusted-client.crt must not validate against the local root" >&2
  exit 1
fi
require_file "${negative_dir}/classical-client.crt"
pqc_require_algorithm x509 "${negative_dir}/classical-client.crt" "rsaEncryption"
require_file "${negative_dir}/mldsa44-client.crt"
pqc_require_algorithm x509 "${negative_dir}/mldsa44-client.crt" "ML-DSA-44"
require_file "${negative_dir}/expired-client.crt"
if pqc_openssl x509 -in "${negative_dir}/expired-client.crt" -noout -checkend 0 >/dev/null 2>&1; then
  echo "expired-client.crt is not expired" >&2
  exit 1
fi
require_file "${negative_dir}/wrong-environment-ca.crt"

echo "runtime-certs-ok (${leaf_algorithm} leaves, ${ca_algorithm} signatures)"
