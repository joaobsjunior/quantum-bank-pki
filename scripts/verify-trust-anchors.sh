#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
# shellcheck source=lib/openssl-pqc.sh
source "${script_dir}/lib/openssl-pqc.sh"
pqc_init "${repo_dir}"

trust_dir="${repo_dir}/local-ca/trust"
root_cert="${trust_dir}/root-ca.crt"
issuing_cert="${trust_dir}/issuing-ca.crt"
ca_algorithm="${QUANTUM_BANK_PQC_CA_ALGORITHM}"

for cert in "${root_cert}" "${issuing_cert}"; do
  if [[ ! -f "${cert}" ]]; then
    echo "missing ${cert}" >&2
    exit 1
  fi
  pqc_openssl x509 -in "${cert}" -noout -text >/dev/null
done

root_subject="$(pqc_openssl x509 -in "${root_cert}" -noout -subject)"
issuing_subject="$(pqc_openssl x509 -in "${issuing_cert}" -noout -subject)"

if [[ "${root_subject}" != *"QuantumBank Local Root CA"* ]]; then
  echo "root CA subject missing QuantumBank Local Root CA" >&2
  exit 1
fi

if [[ "${issuing_subject}" != *"QuantumBank Local Issuing CA"* ]]; then
  echo "issuing CA subject missing QuantumBank Local Issuing CA" >&2
  exit 1
fi

pqc_openssl verify -CAfile "${root_cert}" "${issuing_cert}" >/dev/null

# Post-quantum policy: both anchors carry ML-DSA-87 keys and ML-DSA-87
# signatures. A classical (RSA/EC) anchor would silently downgrade every TLS
# hop that trusts it, so it is rejected here rather than at runtime.
for cert in "${root_cert}" "${issuing_cert}"; do
  pqc_require_algorithm x509 "${cert}" "${ca_algorithm}"
  pqc_require_signature_algorithm "${cert}" "${ca_algorithm}"
done

# When the private keys are present, the anchors must belong to them; a
# mismatch means every signature this CA produces would be unverifiable.
private_dir="${repo_dir}/local-ca/private"
for pair in "root-ca" "issuing-ca"; do
  key="${private_dir}/${pair}.key"
  cert="${trust_dir}/${pair}.crt"
  if [[ -f "${key}" ]]; then
    pqc_require_algorithm key "${key}" "${ca_algorithm}"
    if [[ "$(pqc_openssl pkey -in "${key}" -pubout 2>/dev/null)" != "$(pqc_openssl x509 -in "${cert}" -noout -pubkey)" ]]; then
      echo "${pair} private key does not match ${cert}; rerun scripts/bootstrap-local-ca.sh" >&2
      exit 1
    fi
  fi
done

# CA certificates must never be usable as end-entity TLS certificates.
for cert in "${root_cert}" "${issuing_cert}"; do
  if ! pqc_openssl x509 -in "${cert}" -noout -ext basicConstraints 2>/dev/null | grep -q "CA:TRUE"; then
    echo "${cert} is not marked as a CA certificate" >&2
    exit 1
  fi
done

# The mobile app ships the same root anchor; a drifted copy would make the app
# distrust the real gateway (or trust a stale CA).
mobile_root="${repo_dir}/../mobile-app/assets/local-ca/root-ca.crt"
if [[ -f "${mobile_root}" ]] && ! cmp -s "${root_cert}" "${mobile_root}"; then
  echo "mobile-app/assets/local-ca/root-ca.crt differs from ${root_cert}; rerun scripts/bootstrap-local-ca.sh and commit both" >&2
  exit 1
fi

echo "trust-anchors-ok (${ca_algorithm})"
