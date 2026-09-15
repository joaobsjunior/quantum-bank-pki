#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
trust_dir="${repo_dir}/local-ca/trust"
root_cert="${trust_dir}/root-ca.crt"
issuing_cert="${trust_dir}/issuing-ca.crt"

for cert in "${root_cert}" "${issuing_cert}"; do
  if [[ ! -f "${cert}" ]]; then
    echo "missing ${cert}" >&2
    exit 1
  fi
  openssl x509 -in "${cert}" -noout -text >/dev/null
done

root_subject="$(openssl x509 -in "${root_cert}" -noout -subject)"
issuing_subject="$(openssl x509 -in "${issuing_cert}" -noout -subject)"

if [[ "${root_subject}" != *"QuantumBank Local Root CA"* ]]; then
  echo "root CA subject missing QuantumBank Local Root CA" >&2
  exit 1
fi

if [[ "${issuing_subject}" != *"QuantumBank Local Issuing CA"* ]]; then
  echo "issuing CA subject missing QuantumBank Local Issuing CA" >&2
  exit 1
fi

openssl verify -CAfile "${root_cert}" "${issuing_cert}" >/dev/null

# When the private keys are present, the anchors must belong to them; a
# mismatch means every signature this CA produces would be unverifiable.
private_dir="${repo_dir}/local-ca/private"
for pair in "root-ca" "issuing-ca"; do
  key="${private_dir}/${pair}.key"
  cert="${trust_dir}/${pair}.crt"
  if [[ -f "${key}" ]]; then
    if [[ "$(openssl pkey -in "${key}" -pubout 2>/dev/null)" != "$(openssl x509 -in "${cert}" -noout -pubkey)" ]]; then
      echo "${pair} private key does not match ${cert}; rerun scripts/bootstrap-local-ca.sh" >&2
      exit 1
    fi
  fi
done

# CA certificates must never be usable as end-entity TLS certificates.
for cert in "${root_cert}" "${issuing_cert}"; do
  if ! openssl x509 -in "${cert}" -noout -ext basicConstraints 2>/dev/null | grep -q "CA:TRUE"; then
    echo "${cert} is not marked as a CA certificate" >&2
    exit 1
  fi
done

echo "trust-anchors-ok"

