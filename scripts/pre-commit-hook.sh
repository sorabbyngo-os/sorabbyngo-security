#!/usr/bin/env bash
# Sorabbyngo Pre-commit Secret Scanner
set -euo pipefail
RED='\033[0;31m'; GREEN='\033[0;32m'; NC='\033[0m'; BOLD='\033[1m'
BLOCKED=0
echo -e "${BOLD}[pre-commit] Scanning for secrets...${NC}"
while IFS= read -r file; do
  [[ -f "$file" ]] || continue
  case "$file" in
    *.md|*.example|*.lock|*test*|package-lock.json) continue ;;
  esac
  # Only block actual .env files (not source code)
  if [[ "$file" == ".env" || "$file" == *"/.env" ]] && [[ "$file" != *example* ]]; then
    echo -e "${RED}✗ .env file staged: $file${NC}"; BLOCKED=1
  fi
  # Scan diff for real secrets
  git diff --cached -- "$file" | grep -qEi \
    "(-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY|AKIA[0-9A-Z]{16}|sk-ant-[a-zA-Z0-9]{20,}|JWT_SECRET\s*=\s*['\"][^'\"]{8,}['\"])" && {
    echo -e "${RED}✗ SECRET DETECTED in: $file${NC}"; BLOCKED=1
  }
done < <(git diff --cached --name-only)
[[ $BLOCKED -eq 1 ]] && { echo -e "${RED}${BOLD}COMMIT BLOCKED — remove secrets first${NC}"; exit 1; }
echo -e "${GREEN}✓ No secrets detected${NC}"; exit 0
