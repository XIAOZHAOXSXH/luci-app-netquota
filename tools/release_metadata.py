#!/usr/bin/env python3
"""Validate versions and create deterministic release metadata and checksums."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re

import build_ipk

ROOT = Path(__file__).resolve().parent.parent


def version():
    value = build_ipk.VERSION_DEFAULT
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', value):
        raise ValueError('Release version must be MAJOR.MINOR.PATCH')
    for name in ('netquota', 'luci-app-netquota'):
        makefile = (ROOT / name / 'Makefile').read_text()
        match = re.search(r'^PKG_VERSION:=(\S+)$', makefile, re.M)
        if not match or match[1] != value:
            raise ValueError('Version mismatch: ' + name)
    if 'util.VERSION = "' + value + '"' not in (ROOT / 'netquota/files/usr/lib/lua/netquota/util.lua').read_text():
        raise ValueError('Backend runtime version mismatch')
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets', type=Path)
    args = parser.parse_args()
    current = version()
    tag = os.environ.get('GITHUB_REF_NAME', '')
    stable = os.environ.get('GITHUB_REF_TYPE') == 'tag'
    if stable and tag != 'v' + current:
        raise ValueError('Tag must match source version: v' + current)
    if not stable:
        run = os.environ.get('GITHUB_RUN_NUMBER', 'local')
        tag = 'v' + current + '-build.' + run
    values = {'version': current, 'tag': tag, 'prerelease': str(not stable).lower()}
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
            stream.writelines(key + '=' + value + '\n' for key, value in values.items())
    if args.assets:
        expected = [name + suffix for name in ('netquota', 'luci-app-netquota')
                    for suffix in ('_' + current + '_all.ipk', '-' + current + '-r1.apk')]
        files = sorted(p for p in args.assets.iterdir() if p.suffix in ('.ipk', '.apk'))
        if sorted(p.name for p in files) != sorted(expected):
            raise ValueError('Release requires exactly the four matching IPK/APK packages')
        sums = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        (args.assets / 'SHA256SUMS').write_text(''.join(digest + '  ' + name + '\n' for name, digest in sums.items()))
        provenance = dict(values, commit=os.environ.get('GITHUB_SHA', ''),
                          run_url='https://github.com/' + os.environ.get('GITHUB_REPOSITORY', '') +
                          '/actions/runs/' + os.environ.get('GITHUB_RUN_ID', ''),
                          apk_tool_source='OpenWrt ImageBuilder 25.12.2 x86_64 host tools',
                          assets=sums)
        (args.assets / 'BUILDINFO.json').write_text(json.dumps(provenance, indent=2) + '\n')
    print(json.dumps(values))


if __name__ == '__main__':
    main()
