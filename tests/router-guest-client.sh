#!/bin/sh
# Explicit real-guest integration fixture, not a wireless-air test. Joins the
# existing GL guest bridge and uses its real WAN/NAT; never edits router UCI.
set -eu
case "${1:-}" in
setup)
  ip link show br-guest >/dev/null
  ! ip link show nqr0 >/dev/null 2>&1 || { echo 'nqr0 collision' >&2; exit 1; }
  ! ip netns list | awk '{print $1}' | grep -qx nqrclient || { echo 'namespace collision' >&2; exit 1; }
  [ ! -e /etc/netns/nqrclient ] || { echo 'namespace config collision' >&2; exit 1; }
  ! ip neigh show dev br-guest to 192.168.9.250 | grep -q lladdr || { echo 'test IP already known' >&2; exit 1; }
  ! grep -q ' 192.168.9.250 ' /tmp/dhcp.leases || { echo 'test IP leased' >&2; exit 1; }
  ip netns add nqrclient
  ip link add nqr0 type veth peer name nqr1
  ip link set nqr0 master br-guest
  ip link set nqr0 up
  ip link set nqr1 netns nqrclient
  ip netns exec nqrclient ip link set lo up
  ip netns exec nqrclient ip link set nqr1 address 02:77:09:00:00:fa
  ip netns exec nqrclient ip addr add 192.168.9.250/24 dev nqr1
  ip netns exec nqrclient ip link set nqr1 up
  ip netns exec nqrclient ip route add default via 192.168.9.1
  mkdir -p /etc/netns/nqrclient
  printf 'nameserver 192.168.9.1\n' > /etc/netns/nqrclient/resolv.conf
  echo 'real guest fixture ready; IP outside factory DHCP pool'
  ;;
cleanup)
  for pid in $(ip netns pids nqrclient 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
  ip netns del nqrclient 2>/dev/null || true
  ip link del nqr0 2>/dev/null || true
  if ip neigh show dev br-guest to 192.168.9.250 | grep -q 'lladdr 02:77:09:00:00:fa'; then
    ip neigh del 192.168.9.250 dev br-guest 2>/dev/null || true
  fi
  rm -f /etc/netns/nqrclient/resolv.conf
  rmdir /etc/netns/nqrclient 2>/dev/null || true
  echo 'real guest fixture removed'
  ;;
*) echo 'usage: router-guest-client.sh setup|cleanup' >&2; exit 2 ;;
esac
