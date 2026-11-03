#!/bin/sh
# Run only after the administrator enables the real GL guest through the UI.
# Requires router-guest-client.sh setup. Deletes only its own synthetic account.
set -eu
umask 077
LAB=/tmp/netquota-real-e2e
mkdir -p "$LAB"
id=''
test_username="nqp_$(date +%s)_$$"
cleanup() {
  code=$?
  set +e
  [ -z "$id" ] || ubus call netquota delete_account "{\"id\":$id}" > "$LAB/deleted.json"
  rm -f "$LAB/credentials.json" "$LAB/cookies" "$LAB/login.json"
  exit "$code"
}
trap cleanup EXIT HUP INT TERM
host=$(uci -q get netquota.main.portal_hostname || true)
[ -n "$host" ] || host=$(uci -q get netquota.main.guest_address)
mode=$(uci -q get netquota.main.portal_mode)
if [ "$mode" = https ]; then
  port=$(uci -q get netquota.main.https_port)
  cert=$(uci -q get netquota.main.cert_path)
  set -- --cacert "$cert"
else
  mode=http
  port=$(uci -q get netquota.main.http_port)
  set --
fi
origin="$mode://$host:$port"
ip netns exec nqrclient curl -fsS --max-time 5 "$@" "$origin/cgi-bin/api/status" > "$LAB/status.json"
lua - "$LAB/status.json" <<'LUA'
local f=assert(io.open(arg[1])); local r=require('luci.jsonc').parse(f:read('*a'));f:close(); assert(r.ok)
LUA
echo "PASS real guest portal and DNS ($mode)"
code=$(ip netns exec nqrclient curl -sSI --max-time 5 -o "$LAB/redirect.headers" -w '%{http_code}' http://www.baidu.com/)
[ "$code" = 302 ]
grep -q "Location: $origin/" "$LAB/redirect.headers"
if ip netns exec nqrclient curl -fsSI --max-time 4 https://www.baidu.com/ >/dev/null 2>&1; then
  echo 'Unauthenticated real guest reached Internet' >&2; exit 1
fi
echo 'PASS real guest canonical HTTP redirect and unauthenticated Internet blocked'
ubus call netquota list_accounts '{}' > "$LAB/accounts-before.json"
lua - "$LAB/accounts-before.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a'));f:close();assert(r.ok)
LUA
ubus call netquota create_account "{\"username\":\"$test_username\",\"password\":\"Fixture-only-Guest-123\",\"quota_bytes\":2000000,\"reset_day\":15}" > "$LAB/created.json"
id=$(lua - "$LAB/created.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a'));f:close();assert(r.ok);io.write(r.data.id)
LUA
)
printf '{"username":"%s","password":"Fixture-only-Guest-123"}\n' "$test_username" > "$LAB/credentials.json"
ip netns exec nqrclient curl -fsS --max-time 10 "$@" -c "$LAB/cookies" \
  -H "Origin: $origin" -H 'Content-Type: application/json' --data-binary "@$LAB/credentials.json" \
  "$origin/cgi-bin/api/login" > "$LAB/login.json"
lua - "$LAB/login.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a'));f:close();assert(r.ok and r.data.network_authorized)
LUA
echo "PASS real guest login ($mode)"
ip netns exec nqrclient curl -fsSI --max-time 15 https://www.baidu.com/ > "$LAB/internet.headers"
grep -q '200 OK' "$LAB/internet.headers"
sleep 6
ubus call netquota get_account "{\"id\":$id}" > "$LAB/usage.json"
lua - "$LAB/usage.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a'));f:close()
assert(r.ok and r.data.upload_bytes>0 and r.data.download_bytes>0 and r.data.total_bytes>0 and r.data.session_count==1)
print('PASS real guest Internet via actual uplink; persisted upload='..r.data.upload_bytes..' download='..r.data.download_bytes)
LUA
ubus call netquota update_account "{\"id\":$id,\"quota_bytes\":1}" > "$LAB/exhausted.json"
lua - "$LAB/exhausted.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a'));f:close();assert(r.ok and r.data.exhausted and r.data.remaining_bytes==0)
LUA
if ip netns exec nqrclient curl -fsSI --max-time 4 https://www.baidu.com/ >/dev/null 2>&1; then
  echo 'Exhausted real guest reached Internet' >&2; exit 1
fi
ip netns exec nqrclient curl -fsS --max-time 5 "$@" -b "$LAB/cookies" "$origin/cgi-bin/api/account" > "$LAB/exhausted-portal.json"
lua - "$LAB/exhausted-portal.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a'));f:close();assert(r.ok and r.data.account.exhausted)
LUA
echo 'PASS exhausted real guest blocked while its account portal remains reachable'
echo 'real guest Internet end-to-end: PASS (virtual client on actual guest bridge, not wireless air)'
