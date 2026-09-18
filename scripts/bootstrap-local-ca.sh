#!/usr/bin/env bash
set -euo pipefail

# Bootstraps the two local CA hierarchies:
#   post-quantum chain  root CA    -> ML-DSA-87 key, self-signed (ML-DSA-87)
#                       issuing CA -> ML-DSA-87 key, signed by the root
#   compatibility chain root CA    -> ECDSA P-384 key, self-signed (ecdsa-with-SHA384)
#                       issuing CA -> ECDSA P-384 key, signed by the root
# The compatibility chain only serves the app-facing listeners for peers whose
# TLS stack cannot verify ML-DSA yet (see docs/contracts/certificate-lifecycle.md).
# Requires OpenSSL >= 3.5 (host) or Docker; see scripts/lib/openssl-pqc.sh.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=lib/openssl-pqc.sh
source "${script_dir}/lib/openssl-pqc.sh"
pqc_init "${repo_dir}"

ca_dir="${repo_dir}/local-ca"
private_dir="${ca_dir}/private"
trust_dir="${ca_dir}/trust"
issued_dir="${ca_dir}/issued"
requests_dir="${ca_dir}/requests"
ca_algorithm="${QUANTUM_BANK_PQC_CA_ALGORITHM}"
compat_curve="${QUANTUM_BANK_COMPAT_CA_CURVE}"
compat_family="${QUANTUM_BANK_COMPAT_CA_FAMILY}"
compat_signature="${QUANTUM_BANK_COMPAT_CA_SIGNATURE}"

mkdir -p "${private_dir}" "${trust_dir}" "${issued_dir}" "${requests_dir}"
# Group-traversable (not readable) so the backend container user in PKI_GID
# can open the group-readable issuing key; the root key stays owner-only.
chmod 750 "${private_dir}"
touch "${ca_dir}/index.txt"
if [[ ! -f "${ca_dir}/serial" ]]; then
  printf '1000\n' > "${ca_dir}/serial"
fi

root_key="${private_dir}/root-ca.key"
root_cert="${trust_dir}/root-ca.crt"
issuing_key="${private_dir}/issuing-ca.key"
issuing_csr="${private_dir}/issuing-ca.csr"
issuing_cert="${trust_dir}/issuing-ca.crt"
compat_root_key="${private_dir}/root-ca-compat.key"
compat_root_cert="${trust_dir}/root-ca-compat.crt"
compat_issuing_key="${private_dir}/issuing-ca-compat.key"
compat_issuing_csr="${private_dir}/issuing-ca-compat.csr"
compat_issuing_cert="${trust_dir}/issuing-ca-compat.crt"

echo "post-quantum openssl: $(pqc_openssl_describe)" >&2

# A certificate is only reusable when it was issued for the private key that
# exists on this machine and both use the post-quantum CA algorithm. The trust
# anchors are tracked in Git while private keys never are, so a fresh clone (or
# a CA regenerated elsewhere, or a classical pre-migration anchor) would
# otherwise pair a committed certificate with an unrelated key.
key_matches_cert() {
  local key="$1"
  local cert="$2"
  local family="${3:-${ca_algorithm}}"
  [[ -f "${key}" && -f "${cert}" ]] || return 1
  local key_pub cert_pub
  key_pub="$(pqc_openssl pkey -in "${key}" -pubout 2>/dev/null)" || return 1
  cert_pub="$(pqc_openssl x509 -in "${cert}" -noout -pubkey 2>/dev/null)" || return 1
  [[ -n "${key_pub}" && "${key_pub}" == "${cert_pub}" ]] || return 1
  [[ "$(pqc_key_family x509 "${cert}")" == "${family}" ]]
}

pqc_ensure_key "${root_key}" "${ca_algorithm}" 600

if ! key_matches_cert "${root_key}" "${root_cert}"; then
  echo "issuing a new ${ca_algorithm} root CA certificate for the local root key" >&2
  pqc_openssl req -x509 -new -key "${root_key}" -days 365 \
    -out "${root_cert}" \
    -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Root CA" \
    -config "${ca_dir}/openssl.cnf" -extensions root_ca
  # A new root invalidates the previously issued intermediate.
  rm -f "${issuing_cert}"
fi

# The issuing key is read by the backend container's sign script through the
# PKI_GID group (infrastructure/.env); the root key stays owner-only.
pqc_ensure_key "${issuing_key}" "${ca_algorithm}" 640

pqc_openssl req -new -key "${issuing_key}" -out "${issuing_csr}" \
  -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Issuing CA"

if ! key_matches_cert "${issuing_key}" "${issuing_cert}" ||
  ! pqc_openssl verify -CAfile "${root_cert}" "${issuing_cert}" >/dev/null 2>&1; then
  echo "issuing a new ${ca_algorithm} intermediate CA certificate for the local issuing key" >&2
  pqc_openssl x509 -req -in "${issuing_csr}" \
    -CA "${root_cert}" -CAkey "${root_key}" -CAcreateserial \
    -out "${issuing_cert}" -days 180 \
    -extfile "${ca_dir}/openssl.cnf" -extensions issuing_ca
fi

for anchor in "${root_cert}" "${issuing_cert}"; do
  pqc_require_algorithm x509 "${anchor}" "${ca_algorithm}"
  pqc_require_signature_algorithm "${anchor}" "${ca_algorithm}"
done
chmod 644 "${root_cert}" "${issuing_cert}"

# Compatibility chain: ECDSA P-384 root and issuing CA, ecdsa-with-SHA384
# signatures. Same lifecycle rules as the post-quantum chain; the two chains
# never cross-sign each other.
pqc_ensure_ec_key "${compat_root_key}" "${compat_curve}" "${compat_family}" 600

if ! key_matches_cert "${compat_root_key}" "${compat_root_cert}" "${compat_family}"; then
  echo "issuing a new ${compat_family} compatibility root CA certificate for the local root key" >&2
  pqc_openssl req -x509 -new -key "${compat_root_key}" -sha384 -days 365 \
    -out "${compat_root_cert}" \
    -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Compat Root CA" \
    -config "${ca_dir}/openssl.cnf" -extensions root_ca
  rm -f "${compat_issuing_cert}"
fi

pqc_ensure_ec_key "${compat_issuing_key}" "${compat_curve}" "${compat_family}" 640

pqc_openssl req -new -key "${compat_issuing_key}" -sha384 -out "${compat_issuing_csr}" \
  -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Compat Issuing CA"

if ! key_matches_cert "${compat_issuing_key}" "${compat_issuing_cert}" "${compat_family}" ||
  ! pqc_openssl verify -CAfile "${compat_root_cert}" "${compat_issuing_cert}" >/dev/null 2>&1; then
  echo "issuing a new ${compat_family} compatibility intermediate CA certificate for the local issuing key" >&2
  pqc_openssl x509 -req -in "${compat_issuing_csr}" -sha384 \
    -CA "${compat_root_cert}" -CAkey "${compat_root_key}" -CAcreateserial \
    -out "${compat_issuing_cert}" -days 180 \
    -extfile "${ca_dir}/openssl.cnf" -extensions issuing_ca
fi

for anchor in "${compat_root_cert}" "${compat_issuing_cert}"; do
  pqc_require_family x509 "${anchor}" "${compat_family}"
  pqc_require_signature_algorithm "${anchor}" "${compat_signature}"
done
chmod 644 "${compat_root_cert}" "${compat_issuing_cert}"

# The mobile app bundles both root anchors as assets; keep them in sync when the
# superproject checkout is present so the tracked copies are committed together.
mobile_asset_dir="${repo_dir}/../mobile-app/assets/local-ca"
if [[ -d "${mobile_asset_dir}" ]]; then
  for pair in "${root_cert}:root-ca.crt" "${compat_root_cert}:root-ca-compat.crt"; do
    source_cert="${pair%%:*}"
    asset_name="${pair##*:}"
    if ! cmp -s "${source_cert}" "${mobile_asset_dir}/${asset_name}"; then
      cp "${source_cert}" "${mobile_asset_dir}/${asset_name}"
      echo "updated ${mobile_asset_dir}/${asset_name} with the current root anchor" >&2
    fi
  done
fi

echo "bootstrap-local-ca-ok"
