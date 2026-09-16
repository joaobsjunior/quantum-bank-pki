#!/usr/bin/env bash
set -euo pipefail

# CI validation gate for the pki layer (test-coverage-enforcement capability,
# config/script equivalent). Bootstraps the post-quantum local CA material,
# verifies the trust anchors, generates the runtime certificates and checks
# that every artifact honours the ML-DSA-only policy. Negative mTLS tests
# (negative-mtls-tests.sh) and the PQC handshake tests are excluded here
# because they require a running runtime; they belong to the superproject e2e
# job. Requires OpenSSL >= 3.5 or Docker (scripts/lib/openssl-pqc.sh).

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for step in bootstrap-local-ca.sh verify-trust-anchors.sh bootstrap-runtime-certs.sh verify-runtime-certs.sh; do
  if [[ ! -f "${script_dir}/${step}" ]]; then
    echo "missing pki script: ${script_dir}/${step}" >&2
    exit 1
  fi
  echo "running ${step}"
  bash "${script_dir}/${step}"
done

echo "pki-validate-ok"
