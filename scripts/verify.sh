#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$PATH"

CANDIDATE="${INPUT_CANDIDATE:-}"
BASE="${INPUT_BASE:-}"
BUNDLE_PATH="${INPUT_BUNDLE_PATH:-}"
NOTES_REF="${INPUT_NOTES_REF:-refs/notes/cairnwork}"
FETCH_NOTES="${INPUT_FETCH_NOTES:-true}"
PUBLIC_KEY="${INPUT_PUBLIC_KEY:-}"
CORE_IDENTITY="${INPUT_CORE_IDENTITY:-}"
REQUIRE_WHEN="${INPUT_REQUIRE_WHEN:-label:cairnwork}"
PR_LABELS="${INPUT_PR_LABELS:-[]}"
CHECK_BASE="${INPUT_CHECK_BASE:-true}"

BASE_COMMIT=""
STATEMENT_SHA256=""
KEYID=""

emit_outputs() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf "verdict=%s\ncode=%s\ncandidate=%s\nbase-commit=%s\nstatement-sha256=%s\nkeyid=%s\n" \
      "$1" "$2" "$CANDIDATE" "$BASE_COMMIT" "$STATEMENT_SHA256" "$KEYID" >> "$GITHUB_OUTPUT"
  fi
}

fail() {
  emit_outputs "${3:-REJECTED}" "$1"
  echo "::error::${1}: ${2}"
  exit 1
}

skip() {
  emit_outputs "SKIPPED" "$1"
  echo "::notice::${1}: ${2}"
  exit 0
}

success() {
  emit_outputs "VERIFIED" "OK"
  echo "::notice::OK: Cairnwork attestation verified for candidate ${CANDIDATE}"
  exit 0
}

check_required() {
  if [[ "$REQUIRE_WHEN" == "always" ]]; then echo "true"
  elif [[ "$REQUIRE_WHEN" == "never" ]]; then echo "false"
  elif [[ "$REQUIRE_WHEN" =~ ^label:(.+)$ ]]; then
    local label="${BASH_REMATCH[1]}"
    if [[ -z "$PR_LABELS" || "$PR_LABELS" == "null" ]]; then echo "false"
    elif echo "$PR_LABELS" | jq -e --arg l "$label" 'type == "array" and (index($l) != null)' >/dev/null 2>&1; then echo "true"
    else echo "false"; fi
  else echo "false"; fi
}

prepare_keys() {
  local raw="$1" key_dir="${RUNNER_TEMP:-/tmp}/cairnwork-keys"
  KEY_FILES=()
  mkdir -p "$key_dir" && chmod 700 "$key_dir"
  if [[ "$raw" =~ ^[[:space:]]*-----BEGIN[[:space:]] ]]; then
    local old_umask idx=0 current=""
    old_umask=$(umask) && umask 077
    while IFS= read -r line || [[ -n "$line" ]]; do
      if [[ "$line" =~ -----BEGIN[[:space:]] ]]; then current="${line}"$'\n'
      elif [[ "$line" =~ -----END[[:space:]] ]]; then
        current+="${line}"$'\n'
        local kf="${key_dir}/key-${idx}.pem"
        [[ $idx -eq 0 ]] && kf="${RUNNER_TEMP:-/tmp}/cairnwork-public-key.pem"
        printf "%s" "$current" > "$kf"
        KEY_FILES+=("$kf")
        current="" && idx=$((idx + 1))
      elif [[ -n "$current" ]]; then current+="${line}"$'\n'; fi
    done <<< "$raw"
    umask "$old_umask"
  else
    while IFS= read -r line || [[ -n "$line" ]]; do
      local trimmed; trimmed=$(echo "$line" | xargs)
      [[ -n "$trimmed" ]] && KEY_FILES+=("$trimmed")
    done <<< "$raw"
    local kf
    for kf in "${KEY_FILES[@]}"; do
      [[ -f "$kf" ]] || fail "BAD_INPUT" "public key file not found: ${kf}" "ERROR"
    done
  fi
}

run_verifier() {
  local bundle="$1" verified=false last_exit=0 last_stdout="" last_code=""
  for kf in "${KEY_FILES[@]}"; do
    local cmd=(cairnwork-attest verify "$bundle" --public-key "$kf" --repo . --candidate "$CANDIDATE")
    [[ -n "$CORE_IDENTITY" ]] && cmd+=(--core-identity "$CORE_IDENTITY")
    set +e
    local output; output=$("${cmd[@]}")
    local status=$?
    set -e
    if [[ $status -eq 0 ]]; then verified=true; break; fi
    last_exit=$status; last_stdout="$output"
    last_code=$(echo "$output" | cut -d: -f1 | tr -d '[:space:]')
  done
  if [[ "$verified" == "true" ]]; then success
  elif [[ $last_exit -eq 2 ]]; then fail "VERIFIER_ERROR" "verifier returned usage or IO error" "ERROR"
  else
    local detail="${last_stdout#"$last_code": }"
    [[ "$detail" == "$last_stdout" ]] && detail="${last_stdout#"$last_code":}"
    fail "${last_code:-VERIFIER_REJECTED}" "${detail:-verification failed}" "REJECTED"
  fi
}

# 1. Input validation
[[ "$CANDIDATE" =~ ^[0-9a-f]{40}$ ]] || fail "BAD_INPUT" "candidate must be a 40-hex commit SHA" "ERROR"
[[ "$BASE" =~ ^[0-9a-f]{40}$ ]] || fail "BAD_INPUT" "base must be a 40-hex commit SHA" "ERROR"
[[ -n "$PUBLIC_KEY" ]] || fail "BAD_INPUT" "public-key is required" "ERROR"
if [[ -n "${INPUT_CAIRNWORK_REF:-}" ]] && ! [[ "$INPUT_CAIRNWORK_REF" =~ ^[0-9a-f]{40}$ ]]; then
  fail "BAD_INPUT" "cairnwork-ref must be a 40-hex commit SHA" "ERROR"
fi
case "$REQUIRE_WHEN" in
  always|never|label:?*) ;;
  *) fail "BAD_INPUT" "invalid require-when: ${REQUIRE_WHEN} (always | never | label:<name>)" "ERROR" ;;
esac
IS_REQUIRED=$(check_required)

# 2. Locate or fetch bundle
BUNDLE_FILE=""
if [[ -n "$BUNDLE_PATH" ]]; then
  if [[ ! -f "$BUNDLE_PATH" ]]; then
    [[ "$IS_REQUIRED" == "true" ]] && fail "BUNDLE_MISSING" "bundle file not found: ${BUNDLE_PATH}"
    skip "BUNDLE_MISSING" "bundle file not found: ${BUNDLE_PATH}"
  fi
  BUNDLE_FILE="$BUNDLE_PATH"
else
  if [[ "$FETCH_NOTES" == "true" ]]; then
    if ! git fetch origin "+${NOTES_REF}:${NOTES_REF}" 2>/dev/null; then
      [[ "$IS_REQUIRED" == "true" ]] && fail "NOTES_FETCH_FAILED" "git fetch origin +${NOTES_REF}:${NOTES_REF} failed" "ERROR"
    fi
  fi
  BUNDLE_FILE="${RUNNER_TEMP:-/tmp}/cairnwork-bundle.json"
  if ! git notes --ref "$NOTES_REF" show "$CANDIDATE" > "$BUNDLE_FILE" 2>/dev/null; then
    rm -f "$BUNDLE_FILE"
    [[ "$IS_REQUIRED" == "true" ]] && fail "BUNDLE_MISSING" "no note found on ${NOTES_REF} for candidate ${CANDIDATE}"
    skip "BUNDLE_MISSING" "no note found on ${NOTES_REF} for candidate ${CANDIDATE}"
  fi
fi

# 3. Validate bundle structure
if ! jq -e 'type == "object" and has("payload") and has("payloadType") and has("signatures")' "$BUNDLE_FILE" >/dev/null 2>&1; then
  fail "BUNDLE_MALFORMED" "bundle is not a JSON object with payload, payloadType, signatures"
fi
KEYID=$(jq -r '.signatures[0].keyid // empty' "$BUNDLE_FILE" 2>/dev/null || true)

# 4. Decode payload
PAYLOAD_FILE="${RUNNER_TEMP:-/tmp}/cairnwork-payload.bin"
if ! jq -r .payload "$BUNDLE_FILE" | base64 -d > "$PAYLOAD_FILE" 2>/dev/null; then
  fail "BUNDLE_MALFORMED" "failed to base64-decode payload"
fi

if command -v sha256sum >/dev/null 2>&1; then
  STATEMENT_SHA256=$(sha256sum "$PAYLOAD_FILE" | awk '{print $1}')
else
  STATEMENT_SHA256=$(shasum -a 256 "$PAYLOAD_FILE" | awk '{print $1}')
fi

jq -e 'type == "object"' "$PAYLOAD_FILE" >/dev/null 2>&1 || fail "BUNDLE_MALFORMED" "decoded payload is not a JSON object"
BASE_COMMIT=$(jq -r '.predicate.base_commit // empty' "$PAYLOAD_FILE" 2>/dev/null || true)
[[ "$BASE_COMMIT" =~ ^[0-9a-f]{40}$ ]] || fail "BUNDLE_MALFORMED" "predicate.base_commit is missing or not 40-hex"

# 5. Base commit ancestry check
if [[ "$CHECK_BASE" == "true" ]]; then
  if ! git merge-base --is-ancestor "$BASE_COMMIT" "$BASE" 2>/dev/null; then
    fail "BASE_NOT_IN_TARGET" "predicate.base_commit ${BASE_COMMIT} is not an ancestor of base ${BASE}"
  fi
fi

# 6. Verify attestation
command -v cairnwork-attest >/dev/null 2>&1 || fail "VERIFIER_ERROR" "cairnwork-attest command not found" "ERROR"
prepare_keys "$PUBLIC_KEY"
[[ ${#KEY_FILES[@]} -gt 0 ]] || fail "BAD_INPUT" "no public key provided" "ERROR"
run_verifier "$BUNDLE_FILE"
