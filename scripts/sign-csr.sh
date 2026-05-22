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

mkdir -p "$(dirname "${out_cert_path}")" "${ca_dir}/tmp"
ext_file="$(mktemp "${ca_dir}/tmp/sign-csr-ext.XXXXXX.cnf")"
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

openssl x509 -req \
  -in "${csr_path}" \
  -CA "${ca_dir}/trust/issuing-ca.crt" \
  -CAkey "${ca_dir}/private/issuing-ca.key" \
  -CAcreateserial \
  -out "${out_cert_path}" \
  -days 1 \
  -sha256 \
  -extfile "${ext_file}" \
  -extensions v3_client >/dev/null 2>&1

echo "sign-csr-ok"

