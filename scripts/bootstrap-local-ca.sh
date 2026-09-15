#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
ca_dir="${repo_dir}/local-ca"
private_dir="${ca_dir}/private"
trust_dir="${ca_dir}/trust"
issued_dir="${ca_dir}/issued"
requests_dir="${ca_dir}/requests"

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

# A certificate is only reusable when it was issued for the private key that
# exists on this machine. The trust anchors are tracked in Git while private
# keys never are, so a fresh clone (or a CA regenerated elsewhere) would
# otherwise pair a committed certificate with a brand-new, unrelated key and
# every signature made with that key would fail to verify.
key_matches_cert() {
  local key="$1"
  local cert="$2"
  [[ -f "${key}" && -f "${cert}" ]] || return 1
  local key_pub cert_pub
  key_pub="$(openssl pkey -in "${key}" -pubout 2>/dev/null)" || return 1
  cert_pub="$(openssl x509 -in "${cert}" -noout -pubkey 2>/dev/null)" || return 1
  [[ -n "${key_pub}" && "${key_pub}" == "${cert_pub}" ]]
}

if [[ ! -f "${root_key}" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${root_key}" >/dev/null 2>&1
  chmod 600 "${root_key}"
fi

if ! key_matches_cert "${root_key}" "${root_cert}"; then
  echo "issuing a new root CA certificate for the local root key" >&2
  openssl req -x509 -new -key "${root_key}" -days 365 -sha256 \
    -out "${root_cert}" \
    -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Root CA" \
    -config "${ca_dir}/openssl.cnf" -extensions root_ca
  # A new root invalidates the previously issued intermediate.
  rm -f "${issuing_cert}"
fi

if [[ ! -f "${issuing_key}" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${issuing_key}" >/dev/null 2>&1
fi
# The issuing key is read by the backend container's sign script through the
# PKI_GID group (infrastructure/.env); the root key stays owner-only.
chmod 640 "${issuing_key}"

openssl req -new -key "${issuing_key}" -out "${issuing_csr}" \
  -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Issuing CA"

if ! key_matches_cert "${issuing_key}" "${issuing_cert}" ||
  ! openssl verify -CAfile "${root_cert}" "${issuing_cert}" >/dev/null 2>&1; then
  echo "issuing a new intermediate CA certificate for the local issuing key" >&2
  openssl x509 -req -in "${issuing_csr}" \
    -CA "${root_cert}" -CAkey "${root_key}" -CAcreateserial \
    -out "${issuing_cert}" -days 180 -sha256 \
    -extfile "${ca_dir}/openssl.cnf" -extensions issuing_ca
fi

echo "bootstrap-local-ca-ok"
