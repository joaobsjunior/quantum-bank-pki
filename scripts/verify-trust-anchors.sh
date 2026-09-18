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
compat_root_cert="${trust_dir}/root-ca-compat.crt"
compat_issuing_cert="${trust_dir}/issuing-ca-compat.crt"
compat_family="${QUANTUM_BANK_COMPAT_CA_FAMILY}"
compat_signature="${QUANTUM_BANK_COMPAT_CA_SIGNATURE}"

for cert in "${root_cert}" "${issuing_cert}" "${compat_root_cert}" "${compat_issuing_cert}"; do
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

compat_root_subject="$(pqc_openssl x509 -in "${compat_root_cert}" -noout -subject)"
compat_issuing_subject="$(pqc_openssl x509 -in "${compat_issuing_cert}" -noout -subject)"
if [[ "${compat_root_subject}" != *"QuantumBank Local Compat Root CA"* ]]; then
  echo "compat root CA subject missing QuantumBank Local Compat Root CA" >&2
  exit 1
fi
if [[ "${compat_issuing_subject}" != *"QuantumBank Local Compat Issuing CA"* ]]; then
  echo "compat issuing CA subject missing QuantumBank Local Compat Issuing CA" >&2
  exit 1
fi
pqc_openssl verify -CAfile "${compat_root_cert}" "${compat_issuing_cert}" >/dev/null

# Post-quantum chain: both anchors carry ML-DSA-87 keys and ML-DSA-87
# signatures. A classical anchor here would silently downgrade every strict
# hop that trusts it, so it is rejected here rather than at runtime.
for cert in "${root_cert}" "${issuing_cert}"; do
  pqc_require_algorithm x509 "${cert}" "${ca_algorithm}"
  pqc_require_signature_algorithm "${cert}" "${ca_algorithm}"
done

# Compatibility chain: ECDSA P-384 keys and ecdsa-with-SHA384 signatures only
# (no RSA, no weaker curve), and never cross-signed by the post-quantum chain.
for cert in "${compat_root_cert}" "${compat_issuing_cert}"; do
  pqc_require_family x509 "${cert}" "${compat_family}"
  pqc_require_signature_algorithm "${cert}" "${compat_signature}"
done
if pqc_openssl verify -CAfile "${root_cert}" "${compat_issuing_cert}" >/dev/null 2>&1 ||
  pqc_openssl verify -CAfile "${compat_root_cert}" "${issuing_cert}" >/dev/null 2>&1; then
  echo "the post-quantum and compatibility chains must not cross-sign each other" >&2
  exit 1
fi

# When the private keys are present, the anchors must belong to them; a
# mismatch means every signature this CA produces would be unverifiable.
private_dir="${repo_dir}/local-ca/private"
for pair in "root-ca:${ca_algorithm}" "issuing-ca:${ca_algorithm}" "root-ca-compat:${compat_family}" "issuing-ca-compat:${compat_family}"; do
  name="${pair%%:*}"
  family="${pair##*:}"
  key="${private_dir}/${name}.key"
  cert="${trust_dir}/${name}.crt"
  if [[ -f "${key}" ]]; then
    pqc_require_family key "${key}" "${family}"
    if [[ "$(pqc_openssl pkey -in "${key}" -pubout 2>/dev/null)" != "$(pqc_openssl x509 -in "${cert}" -noout -pubkey)" ]]; then
      echo "${name} private key does not match ${cert}; rerun scripts/bootstrap-local-ca.sh" >&2
      exit 1
    fi
  fi
done

# CA certificates must never be usable as end-entity TLS certificates.
for cert in "${root_cert}" "${issuing_cert}" "${compat_root_cert}" "${compat_issuing_cert}"; do
  if ! pqc_openssl x509 -in "${cert}" -noout -ext basicConstraints 2>/dev/null | grep -q "CA:TRUE"; then
    echo "${cert} is not marked as a CA certificate" >&2
    exit 1
  fi
done

# The mobile app ships the same root anchors; a drifted copy would make the
# app distrust the real gateway (or trust a stale CA).
for pair in "${root_cert}:root-ca.crt" "${compat_root_cert}:root-ca-compat.crt"; do
  source_cert="${pair%%:*}"
  asset_name="${pair##*:}"
  mobile_root="${repo_dir}/../mobile-app/assets/local-ca/${asset_name}"
  if [[ -f "${mobile_root}" ]] && ! cmp -s "${source_cert}" "${mobile_root}"; then
    echo "mobile-app/assets/local-ca/${asset_name} differs from ${source_cert}; rerun scripts/bootstrap-local-ca.sh and commit both" >&2
    exit 1
  fi
done

echo "trust-anchors-ok (${ca_algorithm} post-quantum chain, ${compat_family} compatibility chain)"
