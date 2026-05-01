#!/usr/bin/env bash
HOOK_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/pre-commit-hook.sh"
for repo in ~/sorabbyngo-Labs ~/sorabbyngo-cyberwall ~/sorabbyngo-os ~/sorabbyngo-models ~/sorabbyngo-patches ~/sorabbyngo-security;do
  [[ -d "$repo/.git" ]]&&{ cp "$HOOK_SRC" "$repo/.git/hooks/pre-commit";chmod +x "$repo/.git/hooks/pre-commit";echo "✓ $repo"; }||echo "~ skipped: $repo"
done
echo "Done"
