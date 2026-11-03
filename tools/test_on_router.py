"""Run source tests; --network additionally creates an isolated routed lab."""
import argparse
import io
from pathlib import Path
import shlex
import tarfile
import sys
import router

ROOT=Path(__file__).resolve().parent.parent
STAGE='/tmp/netquota-source-tests'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host',default='192.168.8.1')
    parser.add_argument('--user',default='root')
    parser.add_argument('--port',type=int,default=22)
    parser.add_argument('--fingerprint',required=True)
    parser.add_argument('--timeout',type=float,default=300)
    parser.add_argument('--network',action='store_true')
    parser.add_argument('--temporary-disable-hnat',action='store_true',
                        help='temporarily disable the GL runtime HNAT hook for the lab; restore its configured state on exit')
    args=parser.parse_args()
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w:gz') as tar:
        files=[(p,'lua/netquota/'+p.name) for p in sorted((ROOT/'netquota/files/usr/lib/lua/netquota').glob('*.lua'))]
        files += [(ROOT/'tests'/n,'tests/'+n) for n in ('test_domain.lua','test_rules.lua','test_portal.lua','test_deployment.lua','test_forwarding.lua','router-lab.sh')]
        for source,name in files:
            data=source.read_bytes().replace(b'\r\n',b'\n')
            member=tarfile.TarInfo(name); member.size=len(data); member.mode=0o644
            tar.addfile(member,io.BytesIO(data))
    with router.Connection(args) as conn:
        if args.network:
            conn.run('test "$(uci -q get netquota.main.enabled)" != 1 && '
                     '! nft list table inet netquota >/dev/null 2>&1 && '
                     '! nft list table inet netquota_guard >/dev/null 2>&1')
        conn.run('mkdir -p '+shlex.quote(STAGE)+' && tar -xz -C '+shlex.quote(STAGE),stdin_data=archive.getvalue())
        prefix='LUA_PATH='+shlex.quote(STAGE+'/lua/?.lua;;')+' '
        conn.run(prefix+'lua '+STAGE+'/tests/test_rules.lua')
        conn.run(prefix+'lua '+STAGE+'/tests/test_domain.lua')
        conn.run(prefix+'lua '+STAGE+'/tests/test_portal.lua')
        conn.run(prefix+'lua '+STAGE+'/tests/test_deployment.lua')
        if args.network:
            conn.run('sh '+STAGE+'/tests/router-lab.sh setup')
            try:
                script='set -eu\n'
                if args.temporary_disable_hnat:
                    script += '''saved=$(uci -q get mtkhnat.global.enable)
case "$saved" in 0|1) ;; *) echo 'Cannot determine configured HNAT state' >&2; exit 1 ;; esac
trap 'printf "%s\\n" "$saved" > /sys/kernel/debug/hnat/hook_toggle' EXIT HUP INT TERM
echo 0 > /sys/kernel/debug/hnat/hook_toggle
'''
                script += 'nft delete table inet netquota_lab_guard\n'
                script += 'ip netns exec nqta ping -c 1 -W 1 198.18.78.2\n'
                # Fresh IPv6 neighbour discovery can exceed one second on this
                # firmware. Require a successful baseline before testing drops.
                script += 'ip netns exec nqtc ping -6 -c 2 -W 3 2001:db8:78::2\n'
                script += prefix+'lua '+STAGE+'/tests/test_forwarding.lua\n'
                conn.run('sh -s',stdin_data=script.encode())
            finally:
                conn.run('sh '+STAGE+'/tests/router-lab.sh cleanup')
    return 0

if __name__=='__main__':
    try:
        sys.exit(main())
    except router.CliError as exc:
        print(str(exc),file=sys.stderr)
        sys.exit(exc.code)
