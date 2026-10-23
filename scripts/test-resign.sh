#!/usr/bin/env bash
# test-resign.sh FIXTURE JQ_FILTER OUT KEY: rewrite the payload with JQ_FILTER and sign it with KEY (DSSE, Ed25519)
# Self-test only: builds DSSE bundles under a throwaway key so CI can check version handling
# on correctly signed statements. Not used by the action.
set -euo pipefail
fx=$1 filter=$2 out=$3 key=$4
ptype=$(jq -r .payloadType "$fx")
jq -r .payload "$fx" | base64 -d | jq -c "$filter" | tr -d '\n' > "$out.payload"
{ printf 'DSSEv1 %d %s %d ' "${#ptype}" "$ptype" "$(wc -c < "$out.payload" | tr -d ' ')"; cat "$out.payload"; } > "$out.pae"
openssl pkeyutl -sign -rawin -inkey "$key" -in "$out.pae" -out "$out.sig"
kid=$(openssl pkey -in "$key" -pubout -outform DER | tail -c 32 | openssl dgst -sha256 -r | cut -d' ' -f1)
jq -n --arg t "$ptype" --arg p "$(base64 < "$out.payload" | tr -d '\n')" \
  --arg k "$kid" --arg s "$(base64 < "$out.sig" | tr -d '\n')" \
  '{payloadType: $t, payload: $p, signatures: [{keyid: $k, sig: $s}]}' > "$out"
