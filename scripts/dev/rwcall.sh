#!/usr/bin/env bash
# Calls a TunnixNode Remnawave API like the panel does (mTLS + JWT).
# Usage: rwcall.sh KEYDIR PORT METHOD PATH [JSON_BODY] [zstd]
#   env NOCERT=1 skips the client cert, NOJWT=1 skips the token.
set -u
dir=$1 port=$2 method=$3 path=$4 body=${5:-} enc=${6:-}
args=(-s --tlsv1.3 --resolve "node.local:$port:127.0.0.1" --cacert "$dir/ca.pem" -X "$method")
[[ -z "${NOCERT:-}" ]] && args+=(--cert "$dir/client.pem" --key "$dir/client.key")
[[ -z "${NOJWT:-}" ]] && args+=(-H "Authorization: Bearer $(cat "$dir/jwt.txt")")
if [[ -n "$body" ]]; then
  args+=(-H "Content-Type: application/json")
  if [[ "$enc" == zstd ]]; then
    printf '%s' "$body" | zstd -q -c > "$dir/.body.zst"
    args+=(-H "Content-Encoding: zstd" --data-binary "@$dir/.body.zst")
  else
    args+=(--data-binary "$body")
  fi
fi
/opt/homebrew/opt/curl/bin/curl "${args[@]}" "https://node.local:$port$path" -w '\n[http %{http_code}]'
echo " exit=$?"
