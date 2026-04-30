#!/usr/bin/env bash
set -euo pipefail
SERVICES=(novela karibu dawa pulse taifa dashboard)
PORTS=(18001 18003 18004 18002 18005 3000)
REPORT_DIR="$(dirname "$0")/../audit/logs/scan-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$REPORT_DIR"

command -v trivy &>/dev/null && {
    echo "[SCAN] Running Trivy filesystem scan..."
    trivy fs --severity HIGH,CRITICAL --format json \
        --output "$REPORT_DIR/trivy-fs.json" \
        "$(dirname "$0")/../../sorabbyngo-Labs" 2>/dev/null
} || echo "[WARN] trivy not installed"

command -v nuclei &>/dev/null && {
    echo "[SCAN] Running Nuclei API scans..."
    for i in "${!SERVICES[@]}"; do
        nuclei -u "http://localhost:${PORTS[$i]}" \
            -severity high,critical -tags owasp,api \
            -o "$REPORT_DIR/nuclei-${SERVICES[$i]}.txt" -silent 2>/dev/null || true
    done
} || echo "[WARN] nuclei not installed"

echo "[SCAN] Reports saved to $REPORT_DIR"
