#!/bin/sh
# Isolated routed lab. Never bridges into LAN/WAN or reloads wireless/network.
set -eu

cleanup() {
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null || continue
        "$tool" -D FORWARD -i nqtbr0 -o nqtw0 -j NQT_LAB 2>/dev/null || true
        "$tool" -D FORWARD -i nqtw0 -o nqtbr0 -j NQT_LAB 2>/dev/null || true
        "$tool" -F NQT_LAB 2>/dev/null || true
        "$tool" -X NQT_LAB 2>/dev/null || true
    done
    for ns in nqta nqtb nqtc nqts; do
        for pid in $(ip netns pids "$ns" 2>/dev/null); do kill "$pid" 2>/dev/null || true; done
        ip netns del "$ns" 2>/dev/null || true
    done
    for dev in nqta0 nqtb0 nqtc0 nqtw0 nqtbr0; do ip link del "$dev" 2>/dev/null || true; done
    nft delete table inet netquota_lab_guard 2>/dev/null || true
}

case "${1:-}" in
cleanup)
    cleanup
    echo 'isolated lab removed'
    exit 0
    ;;
setup)
    mkdir -p /tmp/netquota-lab
    # Refuse collisions: do not adopt an unrelated interface or namespace.
    for dev in nqtbr0 nqtw0 nqta0 nqtb0 nqtc0; do
        if ip link show "$dev" >/dev/null 2>&1; then echo "collision: $dev" >&2; exit 1; fi
    done
    for ns in nqta nqtb nqtc nqts; do
        if ip netns list | awk '{print $1}' | grep -qx "$ns"; then echo "collision: $ns" >&2; exit 1; fi
    done
    for tool in iptables ip6tables; do
        if "$tool" -nL NQT_LAB >/dev/null 2>&1; then echo "collision: $tool NQT_LAB" >&2; exit 1; fi
    done
    trap 'cleanup' EXIT HUP INT TERM
    # Guard only this nonexistent-yet test bridge; no other interface matches.
    cat > /tmp/netquota-lab/guard.nft <<'NFT'
add table inet netquota_lab_guard
add chain inet netquota_lab_guard forward { type filter hook forward priority -50; policy accept; }
add rule inet netquota_lab_guard forward iifname "nqtbr0" drop
add rule inet netquota_lab_guard forward oifname "nqtbr0" drop
NFT
    nft -f /tmp/netquota-lab/guard.nft
    ip link add nqtbr0 type bridge
    ip addr add 198.18.77.1/24 dev nqtbr0
    sysctl -qw net.ipv6.conf.nqtbr0.disable_ipv6=0
    sysctl -qw net.ipv6.conf.nqtbr0.forwarding=1
    ip -6 addr add 2001:db8:77::1/64 dev nqtbr0 nodad
    ip link set nqtbr0 up
    idx=2
    for ns in nqta nqtb nqtc; do
        ip netns add "$ns"
        ip link add "${ns}0" type veth peer name "${ns}1"
        ip link set "${ns}0" master nqtbr0
        ip link set "${ns}0" up
        ip link set "${ns}1" netns "$ns"
        ip netns exec "$ns" sysctl -qw net.ipv6.conf.all.disable_ipv6=0
        ip netns exec "$ns" ip link set lo up
        ip netns exec "$ns" ip link set "${ns}1" address "02:00:00:77:00:0${idx}"
        ip netns exec "$ns" ip addr add "198.18.77.${idx}/24" dev "${ns}1"
        ip netns exec "$ns" ip -6 addr add "2001:db8:77::${idx}/64" dev "${ns}1" nodad
        ip netns exec "$ns" ip link set "${ns}1" up
        ip netns exec "$ns" ip route add default via 198.18.77.1
        ip netns exec "$ns" ip -6 route add default via 2001:db8:77::1
        idx=$((idx + 1))
    done
    ip netns add nqts
    ip link add nqtw0 type veth peer name nqtw1
    ip link set nqtw1 netns nqts
    ip netns exec nqts sysctl -qw net.ipv6.conf.all.disable_ipv6=0
    ip addr add 198.18.78.1/24 dev nqtw0
    sysctl -qw net.ipv6.conf.nqtw0.disable_ipv6=0
    sysctl -qw net.ipv6.conf.nqtw0.forwarding=1
    ip -6 addr add 2001:db8:78::1/64 dev nqtw0 nodad
    ip link set nqtw0 up
    ip netns exec nqts ip link set lo up
    ip netns exec nqts ip addr add 198.18.78.2/24 dev nqtw1
    ip netns exec nqts ip -6 addr add 2001:db8:78::2/64 dev nqtw1 nodad
    ip netns exec nqts ip link set nqtw1 up
    ip netns exec nqts ip route add default via 198.18.78.1
    ip netns exec nqts ip -6 route add default via 2001:db8:78::1
    for tool in iptables ip6tables; do
        "$tool" -N NQT_LAB
        "$tool" -A NQT_LAB -j ACCEPT
        "$tool" -I FORWARD 1 -i nqtbr0 -o nqtw0 -j NQT_LAB
        "$tool" -I FORWARD 1 -i nqtw0 -o nqtbr0 -j NQT_LAB
    done
    trap - EXIT HUP INT TERM
    echo 'lab ready: three clients 198.18.77.2-4; server 198.18.78.2; guard CLOSED'
    ;;
*) echo 'usage: router-lab.sh setup|cleanup' >&2; exit 2 ;;
esac
