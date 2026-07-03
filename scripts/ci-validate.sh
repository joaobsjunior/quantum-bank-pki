#!/usr/bin/env bash
set -euo pipefail

# CI validation gate for the pki layer (test-coverage-enforcement capability,
# config/script equivalent). Bootstraps the local CA material and verifies the
# trust anchors. Negative mTLS tests (negative-mtls-tests.sh) are excluded here
# because they require a running runtime; they belong to the superproject e2e
# job.

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate local CA material so trust-anchor verification has certs to inspect.
if [[ -x "${script_dir}/bootstrap-local-ca.sh" || -f "${script_dir}/bootstrap-local-ca.sh" ]]; then
  echo "running bootstrap-local-ca.sh"
  bash "${script_dir}/bootstrap-local-ca.sh"
else
  echo "missing pki script: ${script_dir}/bootstrap-local-ca.sh" >&2
  exit 1
fi

echo "running verify-trust-anchors.sh"
bash "${script_dir}/verify-trust-anchors.sh"

echo "pki-validate-ok"
