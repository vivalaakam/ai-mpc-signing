#!/usr/bin/env bash
# Fail if any non-test source file exceeds MAX_LINES (default 300).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MAX_LINES="${MAX_LINES:-300}"
ALLOWLIST="${ROOT}/scripts/max-lines-allowlist.txt"

is_test_path() {
  case "$1" in
    */tests/* | */e2e/tests/* | */migrations/*) return 0 ;;
  esac
  case "$(basename "$1")" in
    *_e2e.rs | *_test.rs | test_*.rs) return 0 ;;
  esac
  return 1
}

is_allowlisted() {
  [[ -f "$ALLOWLIST" ]] || return 1
  grep -qxF "$1" "$ALLOWLIST"
}

violations=()
while IFS= read -r -d '' file; do
  rel="${file#"$ROOT"/}"
  is_test_path "$rel" && continue
  is_allowlisted "$rel" && continue
  count="$(wc -l < "$file" | tr -d ' ')"
  if (( count > MAX_LINES )); then
    violations+=("$count $rel")
  fi
done < <(
  find "$ROOT/crates" "$ROOT/scripts" -type f \
    \( -name '*.rs' -o -name '*.slint' \) \
    ! -path '*/target/*' -print0 2>/dev/null
)

if ((${#violations[@]} > 0)); then
  echo "Files over ${MAX_LINES} lines (tests/migrations excluded; see scripts/max-lines-allowlist.txt):" >&2
  printf '%s\n' "${violations[@]}" | sort -rn >&2
  echo "Split the file or add to allowlist only for legacy debt being actively reduced." >&2
  exit 1
fi

echo "OK: no non-test sources over ${MAX_LINES} lines (excluding allowlist)."
