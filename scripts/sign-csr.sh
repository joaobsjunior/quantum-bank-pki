#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 6 || $# -gt 7 ]]; then
  echo "usage: sign-csr.sh CSR_PATH OUT_CERT_PATH oauth2Subject appInstanceId deviceId environment [certificateProfile]" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
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

for required in "${csr_path}" "${ca_dir}/trust/issuing-ca.crt" "${ca_dir}/private/issuing-ca.key"; do
  if [[ ! -f "${required}" ]]; then
    echo "missing ${required}" >&2
    exit 1
  fi
done

# Proof of possession: the CSR must be self-signed by the key it certifies.
if ! openssl req -in "${csr_path}" -noout -verify >/dev/null 2>&1; then
  echo "csr signature verification failed" >&2
  exit 1
fi

# Key policy: RSA >= 2048 bits or EC curves with >= 256-bit field.
key_text="$(openssl req -in "${csr_path}" -noout -pubkey 2>/dev/null | openssl pkey -pubin -text -noout 2>/dev/null || true)"
key_bits="$(printf '%s\n' "${key_text}" | sed -n 's/^\(RSA \)\?Public-Key: (\([0-9]*\) bit)$/\2/p' | head -n1)"
if [[ -z "${key_bits}" ]]; then
  echo "unsupported or unreadable csr public key" >&2
  exit 1
fi
if printf '%s\n' "${key_text}" | grep -qi '^modulus:'; then
  if (( key_bits < 2048 )); then
    echo "rsa key too small: ${key_bits} bits" >&2
    exit 1
  fi
elif printf '%s\n' "${key_text}" | grep -q 'ASN1 OID\|NIST CURVE'; then
  if (( key_bits < 256 )); then
    echo "ec key too small: ${key_bits} bits" >&2
    exit 1
  fi
else
  echo "unsupported csr key algorithm" >&2
  exit 1
fi

# Subject binding: exactly one CN and it must equal the OAuth2 subject.
csr_subject="$(openssl req -in "${csr_path}" -noout -subject -nameopt RFC2253,sep_multiline 2>/dev/null || true)"
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
sign_leaf() {
  openssl x509 -req \
    -in "${csr_path}" \
    -CA "${ca_dir}/trust/issuing-ca.crt" \
    -CAkey "${ca_dir}/private/issuing-ca.key" \
    -CAserial "${state_dir}/issuing-ca.srl" \
    -CAcreateserial \
    -out "${out_cert_path}" \
    -days 1 \
    -sha256 \
    -copy_extensions none \
    -extfile "${ext_file}" \
    -extensions v3_client >/dev/null 2>&1
}

if command -v flock >/dev/null 2>&1; then
  (
    flock 9
    sign_leaf
  ) 9>"${state_dir}/issuing-ca.lock"
else
  sign_leaf
fi

echo "sign-csr-ok"
