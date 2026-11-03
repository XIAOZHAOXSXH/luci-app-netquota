#!/usr/bin/env python3
"""Fetch checksum-pinned OpenWrt host tools (Linux x86_64 only).

Only host packaging tools are extracted. No target firmware is installed or run.
Source: https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import urllib.request

VERSION = '25.12.2'
ARCHIVE = 'openwrt-imagebuilder-25.12.2-x86-64.Linux-x86_64.tar.zst'
SHA256 = 'e7842c17855a7e7edb9c30da6999ed74d73626d8f4dd4063e2af61646a5ca8c1'
URL = 'https://downloads.openwrt.org/releases/25.12.2/targets/x86/64/' + ARCHIVE


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default='.build/openwrt-apk')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'amd64'):
        parser.error('requires a Linux x86_64 host; use GitHub Actions on Windows')
    directory = Path(args.directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / ARCHIVE
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != SHA256:
        temp = archive.with_suffix('.download')
        with urllib.request.urlopen(URL, timeout=120) as source, temp.open('wb') as dest:
            while chunk := source.read(1024 * 1024):
                dest.write(chunk)
        if hashlib.sha256(temp.read_bytes()).hexdigest() != SHA256:
            temp.unlink()
            raise SystemExit('OpenWrt ImageBuilder SHA256 mismatch')
        temp.replace(archive)
    subprocess.run(['tar', '--zstd', '-xf', str(archive), '-C', str(directory),
                    '--wildcards', '*/staging_dir/host/*'], check=True)
    apk = next(directory.glob('*/staging_dir/host/bin/apk'))
    subprocess.run([str(apk), '--version'], check=True)
    print('APK_TOOL=' + str(apk))
    if os.environ.get('GITHUB_ENV'):
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as output:
            output.write('APK_TOOL=' + str(apk) + '\n')


if __name__ == '__main__':
    main()
