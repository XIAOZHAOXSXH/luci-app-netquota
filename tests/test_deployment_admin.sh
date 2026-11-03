#!/bin/sh
# Native RPC rejection checks. Requires capture disabled; never enables it.
set -eu
[ "$(uci -q get netquota.main.enabled)" != 1 ] || exit 1
before=$(sha256sum /etc/config/netquota)
check_rejected() {
  reply=$(ubus call netquota "$1" "$2")
  printf '%s' "$reply" | lua -e 'local r=require("luci.jsonc").parse(io.read("*a")); assert(r and r.ok==false and r.error)'
  [ "$(sha256sum /etc/config/netquota)" = "$before" ]
}
check_rejected save_deployment '{"wifi_section":"wifi5g","egress":"apclix0","portal_hostname":""}'
echo 'PASS management SSID cannot be selected through the deployment RPC'
check_rejected save_deployment '{"wifi_section":"guest5g","egress":"br-lan","portal_hostname":""}'
echo 'PASS management interface cannot be selected as the Internet uplink'
check_rejected set_capture '{"enabled":true,"force":true}'
check_rejected get_certificate '{"private":true}'
echo 'PASS unknown arguments and private-key export requests rejected'
check_rejected import_certificate '{"certificate_pem":"-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n","private_key_pem":"invalid key fixture"}'
echo 'PASS invalid certificate/key rejected without changing the active configuration'
ubus call netquota get_certificate '{}' | lua -e 'local r=require("luci.jsonc").parse(io.read("*a"));assert(r.ok and r.data.certificate_pem:find("BEGIN CERTIFICATE",1,true) and not r.data.certificate_pem:find("PRIVATE KEY",1,true))'
echo 'PASS certificate download contains no private key'
echo 'deployment admin RPC: PASS'
