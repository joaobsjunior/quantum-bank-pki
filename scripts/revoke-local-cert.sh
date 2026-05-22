#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: revoke-local-cert.sh CERT_PATH" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
cert_path="$1"
revoked_file="${repo_dir}/local-ca/revoked-serials.txt"

if [[ ! -f "${cert_path}" ]]; then
  echo "missing ${cert_path}" >&2
  exit 1
fi

serial="$(openssl x509 -in "${cert_path}" -noout -serial | cut -d= -f2 | tr '[:lower:]' '[:upper:]')"
if [[ -z "${serial}" ]]; then
  echo "could not extract certificate serial" >&2
  exit 1
fi

touch "${revoked_file}"
if ! grep -Fxq "${serial}" "${revoked_file}"; then
  printf '%s\n' "${serial}" >> "${revoked_file}"
fi

echo "revoke-local-cert-ok"

