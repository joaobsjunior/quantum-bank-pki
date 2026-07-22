#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
ca_dir="${repo_dir}/local-ca"
runtime_dir="${ca_dir}/runtime"
tmp_dir="${ca_dir}/tmp/runtime"
password="${QUANTUM_BANK_RUNTIME_KEYSTORE_PASSWORD:-changeit}"

issuing_cert="${ca_dir}/trust/issuing-ca.crt"
issuing_key="${ca_dir}/private/issuing-ca.key"
root_cert="${ca_dir}/trust/root-ca.crt"

if [[ ! -f "${issuing_cert}" || ! -f "${issuing_key}" ]]; then
  "${script_dir}/bootstrap-local-ca.sh" >/dev/null
fi

mkdir -p "${runtime_dir}" "${tmp_dir}"
chmod 755 "${runtime_dir}"
chmod 700 "${tmp_dir}"

write_ext() {
  local name="$1"
  local eku="$2"
  local sans="$3"
  local ext_file="${tmp_dir}/${name}.ext"

  {
    echo "basicConstraints = critical, CA:FALSE"
    echo "keyUsage = critical, digitalSignature, keyEncipherment"
    echo "extendedKeyUsage = ${eku}"
    echo "subjectAltName = ${sans}"
    echo "subjectKeyIdentifier = hash"
    echo "authorityKeyIdentifier = keyid:always"
  } > "${ext_file}"
}

issue_cert() {
  local name="$1"
  local common_name="$2"
  local eku="$3"
  local sans="$4"
  local key_path="${runtime_dir}/${name}.key"
  local csr_path="${tmp_dir}/${name}.csr"
  local leaf_cert_path="${tmp_dir}/${name}.leaf.crt"
  local cert_path="${runtime_dir}/${name}.crt"
  local ext_path="${tmp_dir}/${name}.ext"

  write_ext "${name}" "${eku}" "${sans}"

  if [[ ! -f "${key_path}" ]]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${key_path}" >/dev/null 2>&1
  fi

  openssl req -new -key "${key_path}" -out "${csr_path}" \
    -subj "/C=BR/O=QuantumBank/OU=local/CN=${common_name}"

  openssl x509 -req -in "${csr_path}" \
    -CA "${issuing_cert}" -CAkey "${issuing_key}" -CAcreateserial \
    -out "${leaf_cert_path}" -days 90 -sha256 \
    -extfile "${ext_path}" >/dev/null 2>&1

  cat "${leaf_cert_path}" "${issuing_cert}" > "${cert_path}"

  chmod 600 "${key_path}"
}

issue_cert \
  "gateway-server" \
  "localhost" \
  "serverAuth" \
  "DNS:localhost,DNS:gateway-bootstrap,DNS:gateway-banking,IP:127.0.0.1"

issue_cert \
  "backend-server" \
  "backend" \
  "serverAuth" \
  "DNS:backend,DNS:localhost,IP:127.0.0.1"

issue_cert \
  "gateway-client" \
  "gateway-client" \
  "clientAuth" \
  "DNS:gateway-client"

issue_cert \
  "mobile-smoke-client" \
  "mobile-smoke-client" \
  "clientAuth" \
  "DNS:mobile-smoke-client"

issue_cert \
  "backend-client" \
  "backend-client" \
  "clientAuth" \
  "DNS:backend-client"

openssl pkcs12 -export \
  -inkey "${runtime_dir}/backend-server.key" \
  -in "${runtime_dir}/backend-server.crt" \
  -certfile "${issuing_cert}" \
  -name backend-server \
  -out "${runtime_dir}/backend-server.p12" \
  -passout "pass:${password}" >/dev/null 2>&1

rm -f "${runtime_dir}/backend-truststore.p12"
keytool -importcert -noprompt \
  -alias root-ca \
  -file "${root_cert}" \
  -keystore "${runtime_dir}/backend-truststore.p12" \
  -storetype PKCS12 \
  -storepass "${password}" >/dev/null 2>&1

keytool -importcert -noprompt \
  -alias issuing-ca \
  -file "${issuing_cert}" \
  -keystore "${runtime_dir}/backend-truststore.p12" \
  -storetype PKCS12 \
  -storepass "${password}" >/dev/null 2>&1

# Service-client keystore + truststore for the external backend-client (mTLS).
openssl pkcs12 -export \
  -inkey "${runtime_dir}/backend-client.key" \
  -in "${runtime_dir}/backend-client.crt" \
  -certfile "${issuing_cert}" \
  -name backend-client \
  -out "${runtime_dir}/backend-client.p12" \
  -passout "pass:${password}" >/dev/null 2>&1

rm -f "${runtime_dir}/backend-client-truststore.p12"
keytool -importcert -noprompt \
  -alias root-ca \
  -file "${root_cert}" \
  -keystore "${runtime_dir}/backend-client-truststore.p12" \
  -storetype PKCS12 \
  -storepass "${password}" >/dev/null 2>&1

keytool -importcert -noprompt \
  -alias issuing-ca \
  -file "${issuing_cert}" \
  -keystore "${runtime_dir}/backend-client-truststore.p12" \
  -storetype PKCS12 \
  -storepass "${password}" >/dev/null 2>&1

cp "${issuing_cert}" "${runtime_dir}/issuing-ca.crt"
cp "${root_cert}" "${runtime_dir}/root-ca.crt"
cat "${issuing_cert}" "${root_cert}" > "${runtime_dir}/ca-chain.crt"
chmod 644 "${runtime_dir}"/*.crt "${runtime_dir}"/*.p12

echo "bootstrap-runtime-certs-ok"
