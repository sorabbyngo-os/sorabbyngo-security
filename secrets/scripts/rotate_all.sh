#!/usr/bin/env bash
set -euo pipefail
LABS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../sorabbyngo-Labs" 2>/dev/null && pwd || echo "$HOME/sorabbyngo-Labs")"
GREEN='\033[0;32m';YELLOW='\033[1;33m';RED='\033[0;31m';NC='\033[0m';BOLD='\033[1m'
log(){ echo -e "${GREEN}[ROTATE]${NC} $*"; }
warn(){ echo -e "${YELLOW}[WARN]${NC} $*"; }
die(){ echo -e "${RED}[ERR]${NC} $*"; exit 1; }
gen(){ openssl rand -base64 64|tr -d '/+='|head -c 64; }
check(){ [[ -f "$LABS_ROOT/.env" ]]||die ".env not found at $LABS_ROOT/.env"; }
bak(){ cp "$LABS_ROOT/.env" "$LABS_ROOT/.env.bak.$(date +%Y%m%d%H%M%S)"; }
set_var(){ local k="$1" v="$2" f="$LABS_ROOT/.env"
  grep -q "^${k}=" "$f"&&sed -i "s|^${k}=.*|${k}=${v}|" "$f"||echo "${k}=${v}">> "$f"; }
rotate_jwt(){ check;bak;set_var JWT_SECRET "$(gen)";log "JWT_SECRET rotated";warn "Sessions invalidated"; }
rotate_checksum(){ check;set_var CHECKSUM_SECRET "$(gen)";log "CHECKSUM_SECRET rotated"; }
status(){
  check
  while IFS= read -r line;do
    [[ "$line"=~^[A-Z_]+=]]||continue
    k="${line%%=*}";v="${line#*=}"
    [[ "$k"==*SECRET*||"$k"==*PASSWORD*||"$k"==*TOKEN*||"$k"==*KEY* ]]||continue
    [[ ${#v} -lt 16 ]]&&echo -e "  ${RED}WEAK${NC}   $k (${#v} chars)"||echo -e "  ${GREEN}OK${NC}     $k (${#v} chars)"
  done<"$LABS_ROOT/.env"
}
case "${1:-status}" in
  jwt) rotate_jwt;;checksum) rotate_checksum;;
  all) rotate_jwt;rotate_checksum;log "Done — restart services";;
  status) status;;
  *) echo "Usage: $0 [all|jwt|checksum|status]";;
esac
