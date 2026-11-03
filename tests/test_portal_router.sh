#!/bin/sh
# End-to-end test on the isolated router-lab.sh topology, using real procd,
# rpcd, uhttpd TLS, SQLite, neighbour lookup, authentication and forwarding.
set -eu
umask 077
LAB=/tmp/netquota-portal-e2e
[ "$(uci -q get netquota.main.enabled)" != 1 ] || { echo 'Capture must be disabled before this test' >&2; exit 1; }
[ -z "$(uci changes netquota)" ] && [ -z "$(uci changes mtkhnat)" ] || { echo 'Refusing pending user UCI changes' >&2; exit 1; }
ip link show nqtbr0 >/dev/null
[ ! -e "$LAB/config.backup" ] || { echo 'Previous test backup requires inspection' >&2; exit 1; }
mkdir -p "$LAB"
cp /etc/config/netquota "$LAB/config.backup"
rm -f "$LAB/ledger.db" "$LAB/ledger.db-wal" "$LAB/ledger.db-shm"
hnat=$(uci -q get mtkhnat.global.enable)
case "$hnat" in 0|1) ;; *) exit 1 ;; esac
cleanup() {
  code=$?
  set +e
  /etc/init.d/netquota stop
  cp "$LAB/config.backup" /etc/config/netquota || { echo 'CRITICAL: restore netquota config failed' >&2; exit 1; }
  uci revert mtkhnat.global.enable
  printf '%s\n' "$hnat" > /sys/kernel/debug/hnat/hook_toggle
  /etc/init.d/netquota start
  mv "$LAB/config.backup" "$LAB/config.restored"
  exit "$code"
}
trap cleanup EXIT HUP INT TERM
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=NetQuota isolated test' \
  -addext 'subjectAltName=IP:198.18.77.1' -keyout "$LAB/key.pem" -out "$LAB/cert.pem" > "$LAB/openssl.log" 2>&1
uci batch <<'UCI'
set netquota.main.enabled=1
set netquota.main.portal_mode=https
set netquota.main.guest=nqtbr0
set netquota.main.guest_address=198.18.77.1
set netquota.main.guest_cidr=198.18.77.0/24
delete netquota.main.egress
add_list netquota.main.egress=nqtw0
set netquota.main.db_path=/tmp/netquota-portal-e2e/ledger.db
set netquota.main.cert_path=/tmp/netquota-portal-e2e/cert.pem
set netquota.main.key_path=/tmp/netquota-portal-e2e/key.pem
commit netquota
set mtkhnat.global.enable=0
UCI
echo 0 > /sys/kernel/debug/hnat/hook_toggle
/etc/init.d/netquota restart
for n in 1 2 3 4 5; do
  if ip netns exec nqta curl -fsS --max-time 2 --cacert "$LAB/cert.pem" https://198.18.77.1:2051/cgi-bin/api/status > "$LAB/status.json"; then break; fi
  sleep 1
done
lua - "$LAB/status.json" <<'LUA'
local f=assert(io.open(arg[1])); local r=assert(require('luci.jsonc').parse(f:read('*a'))); f:close(); assert(r.ok)
LUA
echo 'PASS guest HTTPS certificate verification and service startup'
code=$(ip netns exec nqta curl -sS --max-time 5 -D "$LAB/redirect.headers" -o /dev/null -w '%{http_code}' http://198.18.78.2/)
[ "$code" = 302 ]
grep -q 'Location: https://198.18.77.1:2051/' "$LAB/redirect.headers"
echo 'PASS unauthenticated HTTP redirected to the isolated HTTPS portal'
ubus call netquota create_account '{"username":"lab_alice","password":"Lab-Alice-123","quota_bytes":16000,"reset_day":15}' > "$LAB/alice.json"
ubus call netquota create_account '{"username":"lab_bob","password":"Lab-Bob-123","quota_bytes":50000000000,"reset_day":25}' > "$LAB/bob.json"
lua - "$LAB/alice.json" "$LAB/bob.json" <<'LUA'
local j=require('luci.jsonc'); for i=1,2 do local f=assert(io.open(arg[i]));local r=assert(j.parse(f:read('*a'))); f:close(); assert(r.ok and r.data.id==i); if i==2 then assert(r.data.quota_bytes==50000000000,'64-bit RPC quota truncated') end end
LUA
echo '{"username":"lab_alice","password":"Lab-Alice-123"}' > "$LAB/credentials.json"
for ns in nqta nqtb; do
  ip netns exec "$ns" curl -fsS --max-time 10 --cacert "$LAB/cert.pem" -c "$LAB/$ns.cookies" \
    -H 'Origin: https://198.18.77.1:2051' -H 'Content-Type: application/json' \
    --data-binary "@$LAB/credentials.json" https://198.18.77.1:2051/cgi-bin/api/login > "$LAB/$ns.login.json"
done
echo '{"username":"lab_bob","password":"Lab-Bob-123"}' > "$LAB/credentials.json"
ip netns exec nqtc curl -fsS --max-time 10 --cacert "$LAB/cert.pem" -c "$LAB/nqtc.cookies" \
  -H 'Origin: https://198.18.77.1:2051' -H 'Content-Type: application/json' \
  --data-binary "@$LAB/credentials.json" https://198.18.77.1:2051/cgi-bin/api/login > "$LAB/nqtc.login.json"
lua - "$LAB" <<'LUA'
local j=require('luci.jsonc'); for _,ns in ipairs({'nqta','nqtb','nqtc'}) do local f=assert(io.open(arg[1]..'/'..ns..'.login.json')); local r=j.parse(f:read('*a')); f:close(); assert(r.ok and r.data.network_authorized) end
LUA
echo 'PASS three real HTTPS client sessions and 50GB RPC quota'
ip netns exec nqta ping -c 2 -s 1000 -W 1 198.18.78.2 >/dev/null
ip netns exec nqtb ping -c 2 -s 1000 -W 1 198.18.78.2 >/dev/null
sleep 6
ubus call netquota get_account '{"id":1}' > "$LAB/usage.json"
lua - "$LAB/usage.json" <<'LUA'
local f=assert(io.open(arg[1])); local r=require('luci.jsonc').parse(f:read('*a')); f:close(); assert(r.ok and r.data.total_bytes==8224 and r.data.session_count==2)
LUA
echo 'PASS shared upload/download ledger persisted by the autonomous daemon'
ip netns exec nqta ping -c 10 -s 1000 -W 1 198.18.78.2 >/dev/null 2>&1 || true
if ip netns exec nqtb ping -c 1 -W 1 198.18.78.2 >/dev/null 2>&1; then echo 'Exhausted second client still online' >&2; exit 1; fi
ip netns exec nqtc ping -c 1 -W 1 198.18.78.2 >/dev/null
echo 'PASS exhaustion closes both shared sessions, another account unaffected'
csrf=$(lua - "$LAB/nqta.login.json" <<'LUA'
local f=assert(io.open(arg[1])); local r=require('luci.jsonc').parse(f:read('*a')); f:close(); io.write(r.data.csrf_token)
LUA
)
code=$(ip netns exec nqta curl -sS --max-time 10 --cacert "$LAB/cert.pem" -b "$LAB/nqta.cookies" \
  -H 'Origin: https://198.18.77.1:2051' -H 'Content-Type: application/json' \
  --data-binary '{}' -o "$LAB/rejected.json" -w '%{http_code}' https://198.18.77.1:2051/cgi-bin/api/password)
[ "$code" = 403 ]
echo 'PASS missing CSRF rejected with real HTTP 403'
printf '{"old_password":"Lab-Alice-123","new_password":"Lab-Alice-new-123","confirm_password":"Lab-Alice-new-123","csrf_token":"%s"}\n' "$csrf" > "$LAB/credentials.json"
ip netns exec nqta curl -fsS --max-time 10 --cacert "$LAB/cert.pem" -b "$LAB/nqta.cookies" \
  -H 'Origin: https://198.18.77.1:2051' -H 'Content-Type: application/json' -H "X-CSRF-Token: $csrf" \
  --data-binary "@$LAB/credentials.json" https://198.18.77.1:2051/cgi-bin/api/password > "$LAB/password.json"
lua - "$LAB/password.json" <<'LUA'
local f=assert(io.open(arg[1]));local r=require('luci.jsonc').parse(f:read('*a')); f:close(); assert(r.ok)
LUA
echo 'PASS exhausted account can change its password over verified HTTPS'
/etc/init.d/netquota restart
sleep 2
ubus call netquota get_account '{"id":1}' > "$LAB/restarted.json"
lua - "$LAB/restarted.json" <<'LUA'
local f=assert(io.open(arg[1])); local r=require('luci.jsonc').parse(f:read('*a')); f:close(); assert(r.ok and r.data.exhausted and r.data.total_bytes>=8224 and r.data.remaining_bytes==0)
LUA
ip netns exec nqtc ping -c 1 -W 1 198.18.78.2 >/dev/null
echo 'PASS procd restart preserves usage, exhaustion and the independent account'
echo 'HTTPS portal end-to-end: PASS (configuration and HNAT restored on exit)'
