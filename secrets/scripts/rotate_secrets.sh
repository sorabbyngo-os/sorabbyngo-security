#!/usr/bin/env bash
set -euo pipefail
LABS_ROOT="$(dirname "$0")/../../sorabbyngo-Labs"
gen_secret() { openssl rand -base64 48 | tr -d '/+=' | head -c 64; }

rotate_jwt() {
    local env="$LABS_ROOT/.env"
    [[ -f "$env" ]] || { echo "ERROR: .env not found at $env"; exit 1; }
    cp "$env" "$env.bak.$(date +%Y%m%d%H%M%S)"
    sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(gen_secret)/" "$env"
    echo "[ROTATE] JWT_SECRET rotated — restart services"
}

status() {
    local env="$LABS_ROOT/.env"
    [[ -f "$env" ]] || { echo "ERROR: .env not found"; exit 1; }
    while IFS= read -r line; do
        [[ "$line" =~ ^(JWT|SECRET|KEY|PASSWORD|TOKEN).*= ]] || continue
        local key="${line%%=*}"; local val="${line#*=}"
        [[ ${#val} -lt 32 ]] && echo "WEAK: $key (${#val} chars)" || echo "OK:   $key (${#val} chars)"
    done < "$env"
}

case "${1:-status}" in
    jwt) rotate_jwt ;;
    all) rotate_jwt; echo "Done" ;;
    status) status ;;
    *) echo "Usage: $0 [all|jwt|status]" ;;
esac
