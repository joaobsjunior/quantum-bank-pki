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
chmod 700 "${private_dir}"
touch "${ca_dir}/index.txt"
if [[ ! -f "${ca_dir}/serial" ]]; then
  printf '1000\n' > "${ca_dir}/serial"
fi

root_key="${private_dir}/root-ca.key"
root_cert="${trust_dir}/root-ca.crt"
issuing_key="${private_dir}/issuing-ca.key"
issuing_csr="${private_dir}/issuing-ca.csr"
issuing_cert="${trust_dir}/issuing-ca.crt"

if [[ ! -f "${root_key}" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${root_key}" >/dev/null 2>&1
fi

if [[ ! -f "${root_cert}" ]]; then
  openssl req -x509 -new -key "${root_key}" -days 365 -sha256 \
    -out "${root_cert}" \
    -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Root CA" \
    -config "${ca_dir}/openssl.cnf" -extensions root_ca
fi

if [[ ! -f "${issuing_key}" ]]; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out "${issuing_key}" >/dev/null 2>&1
fi

openssl req -new -key "${issuing_key}" -out "${issuing_csr}" \
  -subj "/C=BR/O=QuantumBank/OU=local/CN=QuantumBank Local Issuing CA"

if [[ ! -f "${issuing_cert}" ]]; then
  openssl x509 -req -in "${issuing_csr}" \
    -CA "${root_cert}" -CAkey "${root_key}" -CAcreateserial \
    -out "${issuing_cert}" -days 180 -sha256 \
    -extfile "${ca_dir}/openssl.cnf" -extensions issuing_ca
fi

echo "bootstrap-local-ca-ok"
