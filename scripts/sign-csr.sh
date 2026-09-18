#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 6 || $# -gt 7 ]]; then
  echo "usage: sign-csr.sh CSR_PATH OUT_CERT_PATH oauth2Subject appInstanceId deviceId environment [certificateProfile]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=lib/openssl-pqc.sh
source "${script_dir}/lib/openssl-pqc.sh"
pqc_init "${repo_dir}"
ca_dir="${repo_dir}/local-ca"

csr_path="$1"
out_cert_path="$2"
oauth2_subject="$3"
app_instance_id="$4"
device_id="$5"
environment="$6"
certificate_profile="${7:-quantum-bank-mobile-client-v1}"

# Every identifier is interpolated into an OpenSSL configuration file and the
# certificate SAN. Reject anything outside a conservative charset so a caller
# can never inject configuration directives (new sections, extensions, comments,
# variable expansion) through these values. The backend validates the same
# formats before the handoff; this is the PKI layer's own guarantee.
require_format() {
  local name="$1"
  local value="$2"
  local pattern="$3"
  if [[ ! "${value}" =~ ${pattern} ]]; then
    echo "invalid ${name}: value does not match the allowed format" >&2
    exit 1
  fi
}

require_format "oauth2Subject" "${oauth2_subject}" '^[A-Za-z0-9][A-Za-z0-9._@-]{0,159}$'
require_format "appInstanceId" "${app_instance_id}" '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
require_format "deviceId" "${device_id}" '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'
require_format "environment" "${environment}" '^[a-z0-9][a-z0-9-]{0,31}$'
require_format "certificateProfile" "${certificate_profile}" '^[a-z0-9][a-z0-9.-]{0,63}$'

if [[ "${certificate_profile}" != "quantum-bank-mobile-client-v1" ]]; then
  echo "unsupported certificate profile: ${certificate_profile}" >&2
  exit 1
fi

if [[ ! -f "${csr_path}" ]]; then
  echo "missing ${csr_path}" >&2
  exit 1
fi

# Proof of possession: the CSR must be self-signed by the key it certifies.
if ! pqc_openssl req -in "${csr_path}" -noout -verify >/dev/null 2>&1; then
  echo "csr signature verification failed" >&2
  exit 1
fi

# Key policy. The mobile profile enrolls ML-DSA-65 keys (ML-DSA-87 accepted)
# under the post-quantum chain, and ECDSA P-256 keys under the compatibility
# chain for devices whose TLS stack cannot present ML-DSA yet. RSA, EdDSA,
# other curves and ML-DSA-44 are rejected so no key the terminators refuse at
# the TLS layer can ever obtain a gateway mTLS identity. The chain is chosen
# by key family: a leaf is never signed by the other family's CA.
key_algorithm="$(pqc_key_family req "${csr_path}" || true)"
chain=""
for candidate in ${QUANTUM_BANK_PQC_ACCEPTED_CSR_ALGORITHMS}; do
  if [[ "${key_algorithm}" == "${candidate}" ]]; then
    chain="pqc"
  fi
done
for candidate in ${QUANTUM_BANK_COMPAT_ACCEPTED_CSR_FAMILIES}; do
  if [[ "${key_algorithm}" == "${candidate}" ]]; then
    chain="compat"
  fi
done
case "${chain}" in
  pqc)
    issuing_cert="${ca_dir}/trust/issuing-ca.crt"
    issuing_key="${ca_dir}/private/issuing-ca.key"
    expected_signature="${QUANTUM_BANK_PQC_CA_ALGORITHM}"
    digest_opt=()
    ;;
  compat)
    issuing_cert="${ca_dir}/trust/issuing-ca-compat.crt"
    issuing_key="${ca_dir}/private/issuing-ca-compat.key"
    expected_signature="${QUANTUM_BANK_COMPAT_CA_SIGNATURE}"
    digest_opt=(-sha384)
    ;;
  *)
    echo "unsupported csr key algorithm: ${key_algorithm:-unreadable} (accepted: ${QUANTUM_BANK_PQC_ACCEPTED_CSR_ALGORITHMS} ${QUANTUM_BANK_COMPAT_ACCEPTED_CSR_FAMILIES})" >&2
    exit 1
    ;;
esac

for required in "${issuing_cert}" "${issuing_key}"; do
  if [[ ! -f "${required}" ]]; then
    echo "missing ${required}" >&2
    exit 1
  fi
done

# Subject binding: exactly one CN and it must equal the OAuth2 subject.
csr_subject="$(pqc_openssl req -in "${csr_path}" -noout -subject -nameopt RFC2253,sep_multiline 2>/dev/null || true)"
csr_cn_count="$(printf '%s\n' "${csr_subject}" | grep -c '^ *CN=' || true)"
csr_cn="$(printf '%s\n' "${csr_subject}" | sed -n 's/^ *CN=//p' | head -n1)"
if [[ "${csr_cn_count}" != "1" || "${csr_cn}" != "${oauth2_subject}" ]]; then
  echo "csr subject CN does not match the authenticated oauth2Subject" >&2
  exit 1
fi

# Mutable state (extension file, serial, lock) lives outside the tracked CA
# tree so the trust anchors, profiles and keys can be mounted read-only. When
# the default state dir is not writable (containers), fall back to the
# process temp dir; serials start random (64-bit) so parallel signers cannot
# collide.
state_dir="${QUANTUM_BANK_PKI_STATE_DIR:-${ca_dir}/tmp}"
if ! mkdir -p "${state_dir}" 2>/dev/null || [[ ! -w "${state_dir}" ]]; then
  state_dir="${TMPDIR:-/tmp}/quantum-bank-pki"
  mkdir -p "${state_dir}"
fi
chmod 700 "${state_dir}" 2>/dev/null || true
mkdir -p "$(dirname "${out_cert_path}")"
ext_file="$(mktemp "${state_dir}/sign-csr-ext.XXXXXX.cnf")"
trap 'rm -f "${ext_file}"' EXIT

cat "${ca_dir}/profiles/quantum-bank-mobile-client-v1.cnf" > "${ext_file}"
{
  echo "subjectAltName = @quantum_bank_mobile_san"
  echo ""
  echo "[quantum_bank_mobile_san]"
  echo "URI.1 = urn:quantum-bank:subject:${oauth2_subject}"
  echo "URI.2 = urn:quantum-bank:app-instance:${app_instance_id}"
  echo "URI.3 = urn:quantum-bank:device:${device_id}"
  echo "URI.4 = urn:quantum-bank:environment:${environment}"
} >> "${ext_file}"

# Serialize issuance so concurrent handoffs can never reuse a serial number.
# The leaf signature follows the chain: ML-DSA-87 for the post-quantum chain,
# ecdsa-with-SHA384 for the compatibility chain.
sign_leaf() {
  pqc_openssl x509 -req "${digest_opt[@]}" \
    -in "${csr_path}" \
    -CA "${issuing_cert}" \
    -CAkey "${issuing_key}" \
    -CAserial "${state_dir}/issuing-ca-${chain}.srl" \
    -CAcreateserial \
    -out "${out_cert_path}" \
    -days 1 \
    -copy_extensions none \
    -extfile "${ext_file}" \
    -extensions v3_client >/dev/null 2>&1
}

if command -v flock >/dev/null 2>&1; then
  (
    flock 9
    sign_leaf
  ) 9>"${state_dir}/issuing-ca-${chain}.lock"
else
  sign_leaf
fi

# Never hand back a certificate whose signature or key family drifted from the
# chain that was selected for it.
pqc_require_signature_algorithm "${out_cert_path}" "${expected_signature}"
pqc_require_family x509 "${out_cert_path}" "${key_algorithm}"

# The issuing certificate of the selected chain travels next to the leaf so the
# caller (backend adapter) can return the right chain without guessing.
cp "${issuing_cert}" "${out_cert_path}.issuer"
chmod 644 "${out_cert_path}.issuer"

echo "sign-csr-ok (${chain}: ${key_algorithm}, ${expected_signature})"
