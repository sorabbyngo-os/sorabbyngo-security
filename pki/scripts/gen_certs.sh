#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_DIR="$SCRIPT_DIR/../ca"
CERTS_DIR="$SCRIPT_DIR/../certs"
SERVICES=(novela karibu dawa pulse taifa dashboard cyberwall nats byngonet)
mkdir -p "$CA_DIR" "$CERTS_DIR"

gen_ca() {
    [[ -f "$CA_DIR/ca.key" ]] && echo "CA exists — skipping" && return
    echo "[PKI] Generating Root CA..."
    openssl genrsa -out "$CA_DIR/ca.key" 4096
    openssl req -new -x509 -key "$CA_DIR/ca.key" -out "$CA_DIR/ca.crt" -days 3650 \
        -subj "/C=KE/ST=Nairobi/O=Sorabbyngo Labs/CN=Sorabbyngo Root CA"
    chmod 600 "$CA_DIR/ca.key"
}

gen_cert() {
    local svc="$1"; local dir="$CERTS_DIR/$svc"; mkdir -p "$dir"
    echo "[PKI] Generating cert for $svc..."
    openssl genrsa -out "$dir/$svc.key" 2048
    openssl req -new -key "$dir/$svc.key" -out "$dir/$svc.csr" \
        -subj "/C=KE/O=Sorabbyngo Labs/CN=$svc.sorabbyngo.internal"
    openssl x509 -req -in "$dir/$svc.csr" -CA "$CA_DIR/ca.crt" -CAkey "$CA_DIR/ca.key" \
        -CAcreateserial -out "$dir/$svc.crt" -days 365
    rm "$dir/$svc.csr"
}

case "${1:-all}" in
    ca) gen_ca ;;
    all) gen_ca; for s in "${SERVICES[@]}"; do gen_cert "$s"; done ;;
    *) echo "Usage: $0 [all|ca]"; exit 1 ;;
esac
