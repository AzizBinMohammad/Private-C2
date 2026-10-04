#!/bin/bash
#
# add-operator.sh -- Generate an operator client certificate signed by
# the Private-C2 CA and write a matching operator configuration file.
#
# Usage:
#   ./scripts/add-operator.sh <operator-name> [certs-directory]
#
# The certificates directory defaults to ./certs and must already
# contain the CA key/cert produced by setup-ca.sh.
#
set -euo pipefail

# ---- args ----
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <operator-name> [certs-directory]" >&2
    exit 1
fi

OPERATOR_NAME="$1"
CERTS_DIR="${2:-certs}"
OPERATOR_DAYS=365
KEY_BITS=4096

CA_KEY="${CERTS_DIR}/ca-key.pem"
CA_CERT="${CERTS_DIR}/ca-cert.pem"

# ---- helpers ----
info()  { echo "[*] $*"; }
warn()  { echo "[!] $*" >&2; }
fatal() { echo "[!!] $*" >&2; exit 1; }

command -v openssl >/dev/null 2>&1 || fatal "openssl is required but not found in PATH"

[[ -f "${CA_KEY}" ]]  || fatal "CA key not found at ${CA_KEY} -- run setup-ca.sh first"
[[ -f "${CA_CERT}" ]] || fatal "CA cert not found at ${CA_CERT} -- run setup-ca.sh first"

# Validate operator name: alphanumeric + hyphens + underscores only.
if [[ ! "${OPERATOR_NAME}" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]]; then
    fatal "Operator name must be alphanumeric (hyphens/underscores allowed, must start with a letter or digit)"
fi

# ---- per-operator output directory ----
OP_DIR="${CERTS_DIR}/operators/${OPERATOR_NAME}"
mkdir -p "${OP_DIR}"

OP_KEY="${OP_DIR}/${OPERATOR_NAME}-key.pem"
OP_CSR="${OP_DIR}/${OPERATOR_NAME}.csr"
OP_CERT="${OP_DIR}/${OPERATOR_NAME}-cert.pem"
OP_EXT="${OP_DIR}/${OPERATOR_NAME}-ext.cnf"
OP_CONFIG="${OP_DIR}/${OPERATOR_NAME}.yaml"

if [[ -f "${OP_KEY}" || -f "${OP_CERT}" ]]; then
    fatal "Operator files already exist in ${OP_DIR}. Remove them first to regenerate."
fi

info "Generating operator key for '${OPERATOR_NAME}' (${KEY_BITS}-bit RSA)"
openssl genrsa -out "${OP_KEY}" "${KEY_BITS}" 2>/dev/null

info "Creating operator CSR"
openssl req -new \
    -key "${OP_KEY}" \
    -out "${OP_CSR}" \
    -subj "/CN=${OPERATOR_NAME}/O=Private-C2/OU=Operators"

# Extension file for client auth.
cat > "${OP_EXT}" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

info "Signing operator certificate with CA (valid ${OPERATOR_DAYS} days)"
openssl x509 -req \
    -in "${OP_CSR}" \
    -CA "${CA_CERT}" \
    -CAkey "${CA_KEY}" \
    -CAcreateserial \
    -out "${OP_CERT}" \
    -days "${OPERATOR_DAYS}" \
    -sha256 \
    -extfile "${OP_EXT}"

chmod 600 "${OP_KEY}"
chmod 644 "${OP_CERT}"

# Clean up intermediary files.
rm -f "${OP_CSR}" "${OP_EXT}" "${CERTS_DIR}/ca-cert.srl"

# ---- operator config file ----
info "Writing operator configuration to ${OP_CONFIG}"
cat > "${OP_CONFIG}" <<EOF
# Private-C2 operator configuration
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

operator:
  name: "${OPERATOR_NAME}"

server:
  address: "localhost:31337"

tls:
  ca_cert: "${CA_CERT}"
  client_cert: "${OP_CERT}"
  client_key: "${OP_KEY}"
EOF

chmod 600 "${OP_CONFIG}"

# ---- print summary ----
echo ""
echo "============================================="
echo "  Operator '${OPERATOR_NAME}' created"
echo "============================================="
echo ""
echo "Files:"
echo "  Certificate : ${OP_CERT}"
echo "  Private key : ${OP_KEY}"
echo "  Config      : ${OP_CONFIG}"
echo ""
echo "Fingerprint:"
openssl x509 -in "${OP_CERT}" -noout -fingerprint -sha256 2>/dev/null || true
echo ""
echo "The operator can connect using:"
echo "  private-c2-client --config ${OP_CONFIG}"
