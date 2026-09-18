#!/usr/bin/env bash
set -euo pipefail

# Generates the runtime material consumed by the local Compose runtime:
#   * post-quantum chain: ML-DSA-65 server/client leaf certificates signed by
#     the ML-DSA-87 issuing CA (every hop), PKCS#12 stores for the JVM
#     services (built with OpenSSL, no JDK needed);
#   * compatibility chain: ECDSA P-256 server certificates for the app-facing
#     listeners (gateway, issuer) signed by the ECDSA P-384 issuing CA, plus
#     the ECDSA smoke client that plays the Dart/BoringSSL mobile role;
#   * PEM bundles for the HAProxy terminators, the union trust bundles, the
#     smoke-test enrollment fixtures (one per key family) and the negative
#     fixtures.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=lib/openssl-pqc.sh
source "${script_dir}/lib/openssl-pqc.sh"
pqc_init "${repo_dir}"

ca_dir="${repo_dir}/local-ca"
runtime_dir="${ca_dir}/runtime"
tmp_dir="${ca_dir}/tmp/runtime"
password="${QUANTUM_BANK_RUNTIME_KEYSTORE_PASSWORD:-changeit}"
leaf_algorithm="${QUANTUM_BANK_PQC_LEAF_ALGORITHM}"
ca_algorithm="${QUANTUM_BANK_PQC_CA_ALGORITHM}"
compat_leaf_curve="${QUANTUM_BANK_COMPAT_LEAF_CURVE}"
compat_leaf_family="${QUANTUM_BANK_COMPAT_LEAF_FAMILY}"
compat_ca_family="${QUANTUM_BANK_COMPAT_CA_FAMILY}"

issuing_cert="${ca_dir}/trust/issuing-ca.crt"
issuing_key="${ca_dir}/private/issuing-ca.key"
root_cert="${ca_dir}/trust/root-ca.crt"
compat_issuing_cert="${ca_dir}/trust/issuing-ca-compat.crt"
compat_issuing_key="${ca_dir}/private/issuing-ca-compat.key"
compat_root_cert="${ca_dir}/trust/root-ca-compat.crt"

if [[ ! -f "${issuing_cert}" || ! -f "${issuing_key}" || ! -f "${compat_issuing_cert}" || ! -f "${compat_issuing_key}" ]] ||
  [[ "$(pqc_public_key_algorithm x509 "${issuing_cert}" || true)" != "${ca_algorithm}" ]] ||
  [[ "$(pqc_key_family x509 "${compat_issuing_cert}" || true)" != "${compat_ca_family}" ]]; then
  "${script_dir}/bootstrap-local-ca.sh" >/dev/null
fi

mkdir -p "${runtime_dir}" "${tmp_dir}"
chmod 755 "${runtime_dir}"
chmod 700 "${tmp_dir}"

echo "post-quantum openssl: $(pqc_openssl_describe)" >&2

write_ext() {
  local name="$1"
  local eku="$2"
  local sans="$3"
  local ext_file="${tmp_dir}/${name}.ext"

  {
    echo "basicConstraints = critical, CA:FALSE"
    echo "keyUsage = critical, digitalSignature"
    echo "extendedKeyUsage = ${eku}"
    echo "subjectAltName = ${sans}"
    echo "subjectKeyIdentifier = hash"
    echo "authorityKeyIdentifier = keyid:always"
  } > "${ext_file}"
}

# issue_cert NAME CN EKU SANS [KEY_ALGORITHM] [KEY_DIR] [CA_CERT] [CA_KEY]
issue_cert() {
  local name="$1"
  local common_name="$2"
  local eku="$3"
  local sans="$4"
  local algorithm="${5:-${leaf_algorithm}}"
  local out_dir="${6:-${runtime_dir}}"
  local ca_cert_path="${7:-${issuing_cert}}"
  local ca_key_path="${8:-${issuing_key}}"
  local key_path="${out_dir}/${name}.key"
  local csr_path="${tmp_dir}/${name}.csr"
  local leaf_cert_path="${tmp_dir}/${name}.leaf.crt"
  local cert_path="${out_dir}/${name}.crt"
  local ext_path="${tmp_dir}/${name}.ext"

  write_ext "${name}" "${eku}" "${sans}"

  # Group-readable so the non-root container users (HAProxy uid 99, the
  # backend service user) can load the key through the PKI_GID group configured
  # in infrastructure/.env; never world-readable.
  local digest_opt=()
  if [[ "${algorithm}" == "${compat_leaf_family}" ]]; then
    pqc_ensure_ec_key "${key_path}" "${compat_leaf_curve}" "${compat_leaf_family}" 640
    # ECDSA signatures need an explicit digest; ML-DSA has none.
    digest_opt=(-sha384)
  else
    pqc_ensure_key "${key_path}" "${algorithm}" 640
  fi

  pqc_openssl req -new -key "${key_path}" -out "${csr_path}" \
    -subj "/C=BR/O=QuantumBank/OU=local/CN=${common_name}"

  pqc_openssl x509 -req -in "${csr_path}" "${digest_opt[@]}" \
    -CA "${ca_cert_path}" -CAkey "${ca_key_path}" -CAcreateserial \
    -out "${leaf_cert_path}" -days 90 \
    -extfile "${ext_path}" >/dev/null 2>&1

  cat "${leaf_cert_path}" "${ca_cert_path}" > "${cert_path}"
  chmod 644 "${cert_path}"

  # HAProxy loads certificate chain + key from one PEM bundle.
  cat "${cert_path}" "${key_path}" > "${out_dir}/${name}.pem"
  chmod 640 "${out_dir}/${name}.pem"
}

# pkcs12_key_store NAME  -> runtime/NAME.p12 (key + leaf + issuing CA)
pkcs12_key_store() {
  local name="$1"
  pqc_openssl pkcs12 -export \
    -inkey "${runtime_dir}/${name}.key" \
    -in "${runtime_dir}/${name}.crt" \
    -certfile "${issuing_cert}" \
    -name "${name}" \
    -out "${runtime_dir}/${name}.p12" \
    -passout "pass:${password}" >/dev/null 2>&1
}

# pkcs12_trust_store NAME -> runtime/NAME.p12 with root + issuing anchors only.
# -jdktrust marks the entries as trusted certificates for the JDK PKCS#12
# reader, which is what keytool used to do.
pkcs12_trust_store() {
  local name="$1"
  rm -f "${runtime_dir}/${name}.p12"
  pqc_openssl pkcs12 -export -nokeys \
    -in "${runtime_dir}/ca-chain.crt" \
    -jdktrust anyExtendedKeyUsage \
    -name "quantum-bank-trust" \
    -out "${runtime_dir}/${name}.p12" \
    -passout "pass:${password}" >/dev/null 2>&1
}

cp "${issuing_cert}" "${runtime_dir}/issuing-ca.crt"
cp "${root_cert}" "${runtime_dir}/root-ca.crt"
cat "${issuing_cert}" "${root_cert}" > "${runtime_dir}/ca-chain.crt"
cp "${compat_issuing_cert}" "${runtime_dir}/issuing-ca-compat.crt"
cp "${compat_root_cert}" "${runtime_dir}/root-ca-compat.crt"
cat "${compat_issuing_cert}" "${compat_root_cert}" > "${runtime_dir}/ca-chain-compat.crt"
# Union bundles for the app-facing listeners: they verify client certificates
# from either chain, and compatibility clients verify servers from either root.
cat "${runtime_dir}/ca-chain.crt" "${runtime_dir}/ca-chain-compat.crt" > "${runtime_dir}/ca-chain-all.crt"
cat "${root_cert}" "${compat_root_cert}" > "${runtime_dir}/trust-anchors.crt"

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

# Keycloak serves the local issuer over post-quantum TLS through its HAProxy
# terminator with a PKI-issued server certificate so no token, JWK, or issuer
# metadata ever travels in plaintext or over a classical handshake.
issue_cert \
  "keycloak-server" \
  "keycloak" \
  "serverAuth" \
  "DNS:keycloak,DNS:localhost,IP:127.0.0.1"

# Compatibility-chain server identities for the app-facing listeners (the
# HAProxy terminators serve them to peers that do not offer ML-DSA signature
# schemes) and the ECDSA smoke client that plays the Dart/BoringSSL mobile role.
issue_cert \
  "gateway-server-compat" \
  "localhost" \
  "serverAuth" \
  "DNS:localhost,DNS:gateway-bootstrap,DNS:gateway-banking,IP:127.0.0.1" \
  "${compat_leaf_family}" "${runtime_dir}" "${compat_issuing_cert}" "${compat_issuing_key}"

issue_cert \
  "keycloak-server-compat" \
  "keycloak" \
  "serverAuth" \
  "DNS:keycloak,DNS:localhost,IP:127.0.0.1" \
  "${compat_leaf_family}" "${runtime_dir}" "${compat_issuing_cert}" "${compat_issuing_key}"

issue_cert \
  "mobile-smoke-client-compat" \
  "mobile-smoke-client-compat" \
  "clientAuth" \
  "DNS:mobile-smoke-client-compat" \
  "${compat_leaf_family}" "${runtime_dir}" "${compat_issuing_cert}" "${compat_issuing_key}"

pkcs12_key_store "backend-server"
pkcs12_trust_store "backend-truststore"

# Service-client keystore + truststore for the external backend-client (mTLS).
pkcs12_key_store "backend-client"
pkcs12_trust_store "backend-client-truststore"

# Enrollment fixture for the e2e smoke test: an ML-DSA-65 CSR whose CN is the
# local Keycloak user id, signed by a throwaway key that stays in the runtime dir.
smoke_subject="${QUANTUM_BANK_SMOKE_SUBJECT:-00000000-0000-0000-0000-000000000001}"
pqc_ensure_key "${runtime_dir}/mobile-smoke-enroll.key" "${leaf_algorithm}" 600
pqc_openssl req -new -key "${runtime_dir}/mobile-smoke-enroll.key" -out "${runtime_dir}/mobile-smoke-enroll.csr" \
  -subj "/CN=${smoke_subject}/O=Quantum Bank/OU=quantum-bank-mobile-client-v1"
chmod 644 "${runtime_dir}/mobile-smoke-enroll.csr"

# Same fixture for the compatibility path: an ECDSA P-256 CSR, which the PKI
# issues under the compatibility chain.
pqc_ensure_ec_key "${runtime_dir}/mobile-smoke-enroll-compat.key" "${compat_leaf_curve}" "${compat_leaf_family}" 600
pqc_openssl req -new -key "${runtime_dir}/mobile-smoke-enroll-compat.key" -sha256 -out "${runtime_dir}/mobile-smoke-enroll-compat.csr" \
  -subj "/CN=${smoke_subject}/O=Quantum Bank/OU=quantum-bank-mobile-client-v1"
chmod 644 "${runtime_dir}/mobile-smoke-enroll-compat.csr"

# Negative-test fixtures: a client certificate from an untrusted CA, an expired
# client certificate from the real issuing CA, a trust anchor from another
# environment, two certificates the real CA signed for keys the policy forbids
# at the TLS layer (classical RSA and the lower ML-DSA-44 category) and an
# ECDSA client certificate from an untrusted compatibility CA.
# negative-mtls-tests.sh refuses to run without them so the fail-closed cases
# can never pass vacuously because a file was missing.
negative_dir="${ca_dir}/negative"
mkdir -p "${negative_dir}"
chmod 700 "${negative_dir}"

pqc_ensure_key "${negative_dir}/untrusted-ca.key" "${ca_algorithm}" 600
pqc_openssl req -x509 -new -key "${negative_dir}/untrusted-ca.key" -days 30 \
  -out "${negative_dir}/untrusted-ca.crt" \
  -subj "/C=BR/O=NotQuantumBank/CN=Untrusted Test CA" \
  -config "${ca_dir}/openssl.cnf" -extensions root_ca >/dev/null 2>&1
cp "${negative_dir}/untrusted-ca.crt" "${negative_dir}/wrong-environment-ca.crt"

issue_cert "untrusted-client" "untrusted-client" "clientAuth" "DNS:untrusted-client" \
  "${leaf_algorithm}" "${negative_dir}" "${negative_dir}/untrusted-ca.crt" "${negative_dir}/untrusted-ca.key"

issue_cert "classical-client" "classical-client" "clientAuth" "DNS:classical-client" \
  "RSA" "${negative_dir}"

pqc_ensure_ec_key "${negative_dir}/untrusted-compat-ca.key" "${QUANTUM_BANK_COMPAT_CA_CURVE}" "${compat_ca_family}" 600
pqc_openssl req -x509 -new -key "${negative_dir}/untrusted-compat-ca.key" -sha384 -days 30 \
  -out "${negative_dir}/untrusted-compat-ca.crt" \
  -subj "/C=BR/O=NotQuantumBank/CN=Untrusted Compat Test CA" \
  -config "${ca_dir}/openssl.cnf" -extensions root_ca >/dev/null 2>&1
issue_cert "untrusted-compat-client" "untrusted-compat-client" "clientAuth" "DNS:untrusted-compat-client" \
  "${compat_leaf_family}" "${negative_dir}" "${negative_dir}/untrusted-compat-ca.crt" "${negative_dir}/untrusted-compat-ca.key"

issue_cert "mldsa44-client" "mldsa44-client" "clientAuth" "DNS:mldsa44-client" \
  "ML-DSA-44" "${negative_dir}"

write_ext "expired-client" "clientAuth" "DNS:expired-client"
pqc_ensure_key "${negative_dir}/expired-client.key" "${leaf_algorithm}" 600
pqc_openssl req -new -key "${negative_dir}/expired-client.key" -out "${tmp_dir}/expired-client.csr" \
  -subj "/C=BR/O=QuantumBank/OU=local/CN=expired-client"
# `x509 -req` cannot backdate, so the expired fixture is issued through
# `openssl ca` with an explicit validity window in the past.
(
  cd "${ca_dir}"
  touch index.txt
  [[ -f serial ]] || printf '1000\n' > serial
  mkdir -p issued
  pqc_openssl ca -batch -config openssl.cnf \
    -in "${tmp_dir}/expired-client.csr" \
    -out "${negative_dir}/expired-client.crt" \
    -startdate 20240101000000Z -enddate 20240102000000Z \
    -extfile "${tmp_dir}/expired-client.ext" -notext >/dev/null 2>&1
)
chmod 600 "${negative_dir}"/*.key
chmod 640 "${negative_dir}"/*.pem 2>/dev/null || true

chmod 644 "${runtime_dir}"/*.crt "${runtime_dir}"/*.p12

echo "bootstrap-runtime-certs-ok"
