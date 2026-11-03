#!/usr/bin/env python3
"""Verify APKv3 integrity and compare every payload file with the matching IPK."""
import argparse
import io
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

import build_ipk


def verify(apk_tool, apk_path, ipk_path):
    subprocess.run([apk_tool, 'verify', '--allow-untrusted', str(apk_path)], check=True)
    metadata = subprocess.check_output([apk_tool, 'adbdump', str(apk_path)], text=True)
    if not re.search(r'\barch:\s*[\"\x27]?noarch\b', metadata):
        raise ValueError('APK must declare arch:noarch')
    for hook in ('post-install', 'pre-upgrade', 'post-upgrade', 'pre-deinstall', 'post-deinstall'):
        if hook not in metadata:
            raise ValueError('APK lifecycle hook missing: ' + hook)
    with tarfile.open(ipk_path, 'r:gz') as outer:
        payload = outer.extractfile('./data.tar.gz').read()
    with tempfile.TemporaryDirectory(prefix='netquota-apk-check-') as directory:
        dest = Path(directory)
        subprocess.run([apk_tool, 'extract', '--allow-untrusted', '--destination', str(dest), str(apk_path)], check=True)
        expected = set()
        with tarfile.open(fileobj=io.BytesIO(payload), mode='r:gz') as archive:
            for item in archive.getmembers():
                if not item.isfile():
                    continue
                name = item.name.removeprefix('./')
                expected.add(name)
                actual = dest / name
                if not actual.is_file() or actual.read_bytes() != archive.extractfile(item).read():
                    raise ValueError('APK/IPK payload mismatch: ' + name)
                if actual.stat().st_mode & 0o777 != item.mode:
                    raise ValueError('APK/IPK mode mismatch: ' + name)
                if actual.stat().st_uid != 0 or actual.stat().st_gid != 0:
                    raise ValueError('APK ownership must be root:root: ' + name)
        actual = {p.relative_to(dest).as_posix() for p in dest.rglob('*') if p.is_file()}
        extra = actual - expected
        if any(not name.startswith('lib/apk/packages/') for name in extra):
            raise ValueError('Unexpected APK payload: ' + repr(sorted(extra)))
        if 'etc/config/netquota' in expected:
            conffiles = (dest / 'lib/apk/packages/netquota.conffiles').read_text()
            if '/etc/config/netquota' not in conffiles.splitlines():
                raise ValueError('APK must preserve the UCI configuration')
    print('PASS APKv3 integrity, metadata, hooks and exact IPK payload:', apk_path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk-tool', required=True)
    parser.add_argument('--directory', default='dist')
    args = parser.parse_args()
    directory = Path(args.directory).resolve()
    for name in ('netquota', 'luci-app-netquota'):
        apk_path = directory / (name + '-' + build_ipk.VERSION_DEFAULT + '-r1.apk')
        ipk_path = directory / (name + '_' + build_ipk.VERSION_DEFAULT + '_all.ipk')
        verify(args.apk_tool, apk_path, ipk_path)


if __name__ == '__main__':
    main()
