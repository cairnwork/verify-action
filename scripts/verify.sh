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
CAIRNWORK_REF="${INPUT_CAIRNWORK_REF:-}"
REQUIRE_WHEN="${INPUT_REQUIRE_WHEN:-always}"
PR_LABELS="${INPUT_PR_LABELS:-[]}"
CHECK_BASE="${INPUT_CHECK_BASE:-ancestor}"

BASE_COMMIT=""
STATEMENT_SHA256=""
KEYID=""

emit_outputs() {
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    local v c cand bc s_sha kid
    v=$(printf "%s" "$1" | tr -d '\r\n')
    c=$(printf "%s" "$2" | tr -d '\r\n')
    cand=$(printf "%s" "$CANDIDATE" | tr -d '\r\n')
    bc=$(printf "%s" "$BASE_COMMIT" | tr -d '\r\n')
    s_sha=$(printf "%s" "$STATEMENT_SHA256" | tr -d '\r\n')
    kid=$(printf "%s" "$KEYID" | tr -d '\r\n')
    printf "verdict=%s\ncode=%s\ncandidate=%s\nbase-commit=%s\nstatement-sha256=%s\nkeyid=%s\n" \
      "$v" "$c" "$cand" "$bc" "$s_sha" "$kid" >> "$GITHUB_OUTPUT"
  fi
}

fail() {
  local code detail verdict="${3:-REJECTED}"
  code=$(printf "%s" "$1" | tr -d '\r\n')
  detail=$(printf "%s" "$2" | tr -d '\r\n')
  emit_outputs "$verdict" "$code"
  echo "::error::${code}: ${detail}"
  exit 1
}

skip() {
  local code detail
  code=$(printf "%s" "$1" | tr -d '\r\n')
  detail=$(printf "%s" "$2" | tr -d '\r\n')
  emit_outputs "SKIPPED" "$code"
  echo "::notice::${code}: ${detail}"
  exit 0
}

success() {
  emit_outputs "VERIFIED" "OK"
  local cand
  cand=$(printf "%s" "$CANDIDATE" | tr -d '\r\n')
  echo "::notice::OK: Cairnwork attestation verified for candidate ${cand}"
  exit 0
}

is_inside_repo() {
  local p="$1" rp
  rp=$(realpath "$p" 2>/dev/null || true)
  [[ -z "$rp" ]] && return 1
  if [[ "$REPO_REALPATH" == "/" ]]; then
    return 0
  fi
  if [[ "$rp" == "$REPO_REALPATH" || "$rp" == "$REPO_REALPATH"/* ]]; then
    return 0
  fi
  return 1
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
      local trimmed="${line#"${line%%[![:space:]]*}"}"
      trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
      [[ -n "$trimmed" ]] && KEY_FILES+=("$trimmed")
    done <<< "$raw"
    local kf
    for kf in "${KEY_FILES[@]}"; do
      [[ "$kf" == /* ]] || fail "BAD_INPUT" "public-key path must be absolute: ${kf}" "ERROR"
      [[ -f "$kf" ]] || fail "BAD_INPUT" "public key file not found: ${kf}" "ERROR"
      if is_inside_repo "$kf"; then
        fail "BAD_INPUT" "public-key must not be inside repo-path: ${kf}" "ERROR"
      fi
    done
  fi
}

run_verifier() {
  local bundle="$1" verified=false last_exit=0 last_stdout="" last_code=""
  for kf in "${KEY_FILES[@]}"; do
    local cmd=("$VERIFIER_BIN" verify "$bundle" --public-key "$kf" --repo . --candidate "$CANDIDATE")
    [[ -n "$CORE_IDENTITY" ]] && cmd+=(--core-identity "$CORE_IDENTITY")
    set +e
    local output; output=$("${cmd[@]}")
    local status=$?
    set -e
    if [[ $status -eq 0 ]]; then verified=true; break; fi
    last_exit=$status; last_stdout="$output"
    last_code=$(printf "%s" "$output" | cut -d: -f1 | tr -d '[:space:]\r\n')
  done
  if [[ "$verified" == "true" ]]; then success
  elif [[ $last_exit -eq 2 ]]; then fail "VERIFIER_ERROR" "verifier returned usage or IO error" "ERROR"
  else
    if ! [[ "$last_code" =~ ^[A-Z_]{1,64}$ ]]; then
      last_code="VERIFIER_REJECTED"
    fi
    local detail="${last_stdout#"$last_code": }"
    [[ "$detail" == "$last_stdout" ]] && detail="${last_stdout#"$last_code":}"
    detail=$(printf "%s" "$detail" | tr -d '\r\n')
    fail "$last_code" "${detail:-verification failed}" "REJECTED"
  fi
}

# 1. Tool check
for tool in jq git base64; do
  command -v "$tool" >/dev/null 2>&1 || fail "MISSING_TOOL" "required tool missing: $tool" "ERROR"
done

REPO_REALPATH="$(realpath .)"

# 2. Input validation
[[ "$CANDIDATE" =~ ^[0-9a-f]{40}$ ]] || fail "BAD_INPUT" "candidate must be a 40-hex commit SHA" "ERROR"
[[ "$BASE" =~ ^[0-9a-f]{40}$ ]] || fail "BAD_INPUT" "base must be a 40-hex commit SHA" "ERROR"
[[ -n "$PUBLIC_KEY" ]] || fail "BAD_INPUT" "public-key is required" "ERROR"
if [[ -n "$CAIRNWORK_REF" ]] && ! [[ "$CAIRNWORK_REF" =~ ^[0-9a-f]{40}$ ]]; then
  fail "BAD_INPUT" "cairnwork-ref must be a 40-hex commit SHA" "ERROR"
fi
if [[ -n "$CORE_IDENTITY" ]]; then
  [[ "$CORE_IDENTITY" == /* ]] || fail "BAD_INPUT" "core-identity path must be absolute" "ERROR"
  [[ -f "$CORE_IDENTITY" ]] || fail "BAD_INPUT" "core-identity file not found: $CORE_IDENTITY" "ERROR"
  if is_inside_repo "$CORE_IDENTITY"; then
    fail "BAD_INPUT" "core-identity must not be inside repo-path" "ERROR"
  fi
fi
case "$CHECK_BASE" in
  ancestor|true|exact|false) ;;
  *) fail "BAD_INPUT" "invalid check-base: ${CHECK_BASE} (ancestor | exact | false)" "ERROR" ;;
esac
case "$REQUIRE_WHEN" in
  always) IS_REQUIRED="true" ;;
  never) IS_REQUIRED="false" ;;
  label:?*)
    target_label="${REQUIRE_WHEN#label:}"
    if ! printf "%s" "$PR_LABELS" | jq -e 'type == "array"' >/dev/null 2>&1; then
      fail "BAD_INPUT" "pr-labels must be a JSON array" "ERROR"
    fi
    if printf "%s" "$PR_LABELS" | jq -e --arg l "$target_label" 'index($l) != null' >/dev/null 2>&1; then
      IS_REQUIRED="true"
    else
      IS_REQUIRED="false"
    fi
    ;;
  *) fail "BAD_INPUT" "invalid require-when: ${REQUIRE_WHEN} (always | never | label:<name>)" "ERROR" ;;
esac

# 3. Locate or fetch bundle
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

# 4. Validate bundle structure
if ! jq -e 'type == "object" and has("payload") and has("payloadType") and has("signatures")' "$BUNDLE_FILE" >/dev/null 2>&1; then
  fail "BUNDLE_MALFORMED" "bundle is not a JSON object with payload, payloadType, signatures"
fi
KEYID=$(jq -r '.signatures[0].keyid // empty' "$BUNDLE_FILE" 2>/dev/null || true)
if ! [[ "$KEYID" =~ ^[A-Za-z0-9._:-]{1,128}$ ]]; then
  KEYID=""
fi

# 5. Decode payload
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

# 6. Base commit check
case "$CHECK_BASE" in
  ancestor|true)
    if ! git merge-base --is-ancestor "$BASE_COMMIT" "$BASE" 2>/dev/null; then
      fail "BASE_NOT_IN_TARGET" "predicate.base_commit ${BASE_COMMIT} is not an ancestor of base ${BASE}"
    fi
    ;;
  exact)
    if [[ "$BASE_COMMIT" != "$BASE" ]]; then
      fail "BASE_NOT_IN_TARGET" "predicate.base_commit ${BASE_COMMIT} does not match base ${BASE}"
    fi
    ;;
  false)
    ;;
esac

# 7. Verify attestation
VERIFIER_BIN="${CAIRNWORK_ATTEST_BIN:-}"
if [[ -z "$VERIFIER_BIN" ]]; then
  VERIFIER_BIN="$(command -v cairnwork-attest 2>/dev/null || true)"
fi
if [[ -z "$VERIFIER_BIN" || ! -x "$VERIFIER_BIN" ]]; then
  fail "VERIFIER_ERROR" "cairnwork-attest command not found" "ERROR"
fi
prepare_keys "$PUBLIC_KEY"
[[ ${#KEY_FILES[@]} -gt 0 ]] || fail "BAD_INPUT" "no public key provided" "ERROR"
run_verifier "$BUNDLE_FILE"
