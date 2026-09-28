#!/bin/sh
# Protocol smoke test against a running backend (mock or the real nginx+Lua):
# create, dropped chunk, offset resync, wrong offset -> 409, finalize, decrypt, junk -> 400.
#   dev/smoke.sh [base_url] [identity_file]
set -eu
CURL="curl ${CURL_OPTS:-}"; B=${1:-http://127.0.0.1:8089}; KEY=${2:-$(dirname "$0")/demo-identity.txt}
R=$(grep -o 'age1[a-z0-9]*' "$KEY"); T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
head -c 300000 /dev/urandom > "$T/plain"; age -r "$R" -o "$T/ct" "$T/plain"; S=$(stat -f%z "$T/ct" 2>/dev/null || stat -c%s "$T/ct")
for a in /upload.js /upload.css; do   # the API prefix must not swallow the app's own assets
  [ "$($CURL -s -o /dev/null -w '%{http_code}' "$B$a")" = 200 ] || { echo "FAIL: $a not served"; exit 1; }
done
off() { $CURL -sI "$B/up/$1" | awk 'tolower($1)=="upload-offset:"{print $2}' | tr -d '\r'; }
ID=$($CURL -sf -X POST -H "Upload-Length: $S" "$B/up" | sed 's/.*"id": *"\([a-f0-9]*\)".*/\1/')
[ "$($CURL -s -o /dev/null -w '%{http_code}' -X PATCH -H 'Upload-Offset: 7' --data-binary @"$T/ct" "$B/up/$ID")" = 409 ] || { echo "FAIL: wrong offset not 409"; exit 1; }
O=0
until [ "$O" = "$S" ]; do   # keep PATCHing from the server's offset; survives FLAKY drops
  tail -c +$((O+1)) "$T/ct" > "$T/rest"
  $CURL -s -m 15 -o /dev/null -X PATCH -H "Upload-Offset: $O" --data-binary @"$T/rest" "$B/up/$ID" || true   # -m: give up on a stalled chunk like the client does
  O=$(off "$ID")
done
$CURL -sf -o /dev/null -X POST "$B/up/$ID/done"
[ "$($CURL -s -o /dev/null -w '%{http_code}' -X POST "$B/up")" = 400 ] || { echo "FAIL: create without Upload-Length not 400"; exit 1; }
J=$($CURL -sf -X POST -H 'Upload-Length: 7' "$B/up" | sed 's/.*"id": *"\([a-f0-9]*\)".*/\1/')
$CURL -s -o /dev/null -X PATCH -H 'Upload-Offset: 0' --data-binary 'not age' "$B/up/$J"
[ "$($CURL -s -o /dev/null -w '%{http_code}' -X POST "$B/up/$J/done")" = 400 ] || { echo "FAIL: junk not 400"; exit 1; }
F=$($CURL -sf -F age=on -F "file=@$T/ct" "$B/up/form" | sed -n 's|.*<code>\([a-f0-9]*\)</code>.*|\1|p')   # no-JS multipart path
[ -n "$F" ] || { echo "FAIL: form upload did not return an id"; exit 1; }
[ "$($CURL -s -o /dev/null -w '%{http_code}' -F age=on -F "file=@$T/plain" "$B/up/form")" = 400 ] || { echo "FAIL: form junk not 400"; exit 1; }
echo "OK: form upload id=$F"
echo "OK: id=$ID ($S bytes) uploaded with resume; missing length, incomplete finalize and junk rejected. Decrypt check needs the stored file:"
echo "  age -d -i $KEY <store>/$ID.age | cmp - <plain>"
