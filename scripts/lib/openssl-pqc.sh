#!/usr/bin/env bash
# Shared post-quantum OpenSSL resolution for every PKI script.
#
# The Quantum Bank PKI is post-quantum only: CA keys are ML-DSA-87, every leaf
# key is ML-DSA-65, and the TLS runtime negotiates X25519MLKEM768 with ML-DSA
# signature schemes. Native ML-DSA (FIPS 204) support requires OpenSSL >= 3.5,
# so this library resolves such a binary once and exposes `pqc_openssl`:
#
#   - the host `openssl` when it is >= 3.5 (for example inside the backend
#     runtime image, or on an up-to-date workstation);
#   - otherwise a pinned container image (`alpine/openssl`) with the PKI tree
#     and the temp dir mounted at the same absolute paths, running as the
#     invoking user so generated material keeps host ownership;
#   - otherwise it fails closed: no classical fallback exists on purpose.
#
# Usage (from a script): source "${script_dir}/lib/openssl-pqc.sh"; pqc_init "${repo_dir}"

QUANTUM_BANK_PQC_OPENSSL_MIN_MAJOR=3
QUANTUM_BANK_PQC_OPENSSL_MIN_MINOR=5
QUANTUM_BANK_PQC_OPENSSL_IMAGE="${QUANTUM_BANK_PQC_OPENSSL_IMAGE:-alpine/openssl:3.5.8}"

# Algorithm policy shared by every layer (see docs/contracts/certificate-lifecycle.md).
QUANTUM_BANK_PQC_CA_ALGORITHM="ML-DSA-87"
QUANTUM_BANK_PQC_LEAF_ALGORITHM="ML-DSA-65"
QUANTUM_BANK_PQC_ACCEPTED_CSR_ALGORITHMS="ML-DSA-65 ML-DSA-87"
QUANTUM_BANK_PQC_TLS_GROUPS="X25519MLKEM768"
QUANTUM_BANK_PQC_TLS_SIGALGS="mldsa65:mldsa87"

_pqc_mode=""
_pqc_host_bin=""
_pqc_root=""

pqc_openssl_version_ok() {
  local bin="$1"
  local version major minor
  version="$("${bin}" version 2>/dev/null | awk '{print $2}')" || return 1
  major="${version%%.*}"
  minor="${version#*.}"
  minor="${minor%%.*}"
  [[ "${major}" =~ ^[0-9]+$ && "${minor}" =~ ^[0-9]+$ ]] || return 1
  (( major > QUANTUM_BANK_PQC_OPENSSL_MIN_MAJOR ||
    (major == QUANTUM_BANK_PQC_OPENSSL_MIN_MAJOR && minor >= QUANTUM_BANK_PQC_OPENSSL_MIN_MINOR) ))
}

# pqc_init <pki repo root>
pqc_init() {
  _pqc_root="$(cd "$1" && pwd)"
  if [[ -n "${QUANTUM_BANK_PQC_OPENSSL:-}" ]]; then
    if ! pqc_openssl_version_ok "${QUANTUM_BANK_PQC_OPENSSL}"; then
      echo "QUANTUM_BANK_PQC_OPENSSL=${QUANTUM_BANK_PQC_OPENSSL} is not OpenSSL >= 3.5" >&2
      return 1
    fi
    _pqc_mode="host"
    _pqc_host_bin="${QUANTUM_BANK_PQC_OPENSSL}"
  elif command -v openssl >/dev/null 2>&1 && pqc_openssl_version_ok openssl; then
    _pqc_mode="host"
    _pqc_host_bin="openssl"
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    _pqc_mode="docker"
  else
    echo "post-quantum PKI requires OpenSSL >= 3.5 (native ML-DSA) on the host, or Docker to run ${QUANTUM_BANK_PQC_OPENSSL_IMAGE}" >&2
    return 1
  fi
}

pqc_openssl_describe() {
  case "${_pqc_mode}" in
    host) echo "host $("${_pqc_host_bin}" version)" ;;
    docker) echo "container ${QUANTUM_BANK_PQC_OPENSSL_IMAGE}" ;;
    *) echo "unresolved (call pqc_init first)" ;;
  esac
}

pqc_openssl() {
  case "${_pqc_mode}" in
    host)
      "${_pqc_host_bin}" "$@"
      ;;
    docker)
      local tmp_root="${TMPDIR:-/tmp}"
      docker run --rm -i \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp \
        -v "${_pqc_root}:${_pqc_root}" \
        -v "${tmp_root}:${tmp_root}" \
        -w "${PWD}" \
        "${QUANTUM_BANK_PQC_OPENSSL_IMAGE}" "$@"
      ;;
    *)
      echo "pqc_openssl used before pqc_init" >&2
      return 1
      ;;
  esac
}

# Public key algorithm name of a certificate (x509), request (req) or private key (key).
# The OpenSSL output is captured before any filtering so an early-closing
# pipe reader can never SIGPIPE the (possibly containerised) openssl process
# under `set -o pipefail`.
pqc_public_key_algorithm() {
  local kind="$1"
  local file="$2"
  local text
  case "${kind}" in
    x509) text="$(pqc_openssl x509 -in "${file}" -noout -text 2>/dev/null)" || return 1
      printf '%s\n' "${text}" | sed -n 's/^ *Public Key Algorithm: //p' | head -n1 ;;
    req) text="$(pqc_openssl req -in "${file}" -noout -text 2>/dev/null)" || return 1
      printf '%s\n' "${text}" | sed -n 's/^ *Public Key Algorithm: //p' | head -n1 ;;
    key) text="$(pqc_openssl pkey -in "${file}" -noout -text 2>/dev/null)" || return 1
      printf '%s\n' "${text}" | sed -n 's/^\([A-Za-z0-9-]*\) Private-Key:.*/\1/p' | head -n1 ;;
    *) echo "unknown kind ${kind}" >&2; return 1 ;;
  esac
}

# Signature algorithm of a certificate (the issuer's key algorithm for ML-DSA).
pqc_signature_algorithm() {
  local text
  text="$(pqc_openssl x509 -in "$1" -noout -text 2>/dev/null)" || return 1
  printf '%s\n' "${text}" | sed -n 's/^ *Signature Algorithm: //p' | head -n1
}

pqc_require_algorithm() {
  local kind="$1"
  local file="$2"
  local expected="$3"
  local actual
  actual="$(pqc_public_key_algorithm "${kind}" "${file}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${file}: public key algorithm is '${actual:-unknown}', expected ${expected}" >&2
    return 1
  fi
}

pqc_require_signature_algorithm() {
  local file="$1"
  local expected="$2"
  local actual
  actual="$(pqc_signature_algorithm "${file}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "${file}: signature algorithm is '${actual:-unknown}', expected ${expected}" >&2
    return 1
  fi
}

# Ensures a private key file exists with the given algorithm. A pre-existing key
# with another algorithm (for example a classical RSA key from before the
# post-quantum migration) is moved aside, never silently reused.
pqc_ensure_key() {
  local key="$1"
  local algorithm="$2"
  local mode="$3"
  if [[ -f "${key}" ]]; then
    local current
    current="$(pqc_public_key_algorithm key "${key}" || true)"
    if [[ "${current}" == "${algorithm}" ]]; then
      chmod "${mode}" "${key}"
      return 0
    fi
    local legacy="${key}.pre-pqc.$(date +%Y%m%d%H%M%S)"
    echo "replacing ${key} (${current:-unreadable}) with a fresh ${algorithm} key; previous key kept at ${legacy}" >&2
    mv "${key}" "${legacy}"
    chmod 600 "${legacy}"
  fi
  pqc_openssl genpkey -algorithm "${algorithm}" -out "${key}" >/dev/null 2>&1
  chmod "${mode}" "${key}"
}
