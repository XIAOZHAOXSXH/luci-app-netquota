#!/usr/bin/env python3
"""Create OpenWrt APKv3 packages with the official apk mkpkg tool.

Shares the exact source allowlist, permissions and maintainer scripts with the
tested IPK builder. Run as root on Linux; output packages are unsigned.
"""
import argparse
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

import build_ipk as ipk

PROJECT_URL = 'https://github.com/XIAOZHAOXSXH/luci-app-netquota'


def stage_payload(spec, dest):
    entries = ipk.collect_entries(spec)
    with tarfile.open(fileobj=io.BytesIO(ipk.build_data_tar(entries))) as archive:
        archive.extractall(dest, filter='data')
    metadata = dest / 'lib/apk/packages'
    metadata.mkdir(parents=True, exist_ok=True)
    conffiles = ipk._conffiles(entries, spec)
    if conffiles:
        (metadata / (spec.name + '.conffiles')).write_text('\n'.join(conffiles) + '\n')
        checks = [name + ' ' + hashlib.sha256((dest / name.lstrip('/')).read_bytes()).hexdigest()
                  for name in conffiles]
        (metadata / (spec.name + '.conffiles_static')).write_text('\n'.join(checks) + '\n')
    listing = sorted('/' + p.relative_to(dest).as_posix() for p in dest.rglob('*') if p.is_file())
    (metadata / (spec.name + '.list')).write_text('\n'.join(listing) + '\n')
    for path in sorted(dest.rglob('*'), reverse=True):
        if path.is_dir():
            path.chmod(0o755)
        elif path.is_file() and path.parent == metadata:
            path.chmod(0o644)
        os.utime(path, (ipk.current_epoch(), ipk.current_epoch()))
    dest.chmod(0o755)
    os.utime(dest, (ipk.current_epoch(), ipk.current_epoch()))


def lifecycle_scripts(spec, repo_root):
    canonical = ipk._script_bytes(str(repo_root), spec)
    header = '#!/bin/sh\n[ "${IPKG_NO_SCRIPT}" = 1 ] && exit 0\n[ -n "${IPKG_INSTROOT}" ] && exit 0\n'
    functions = ('if [ -s /lib/functions.sh ]; then\n . /lib/functions.sh\n'
                 ' export root="" pkgname=' + spec.name + '\n')

    def wrap(script, upgrade=False, default=None):
        body = header + ('export PKG_UPGRADE=1\n' if upgrade else '')
        # Execute canonical scripts first, in a subshell: their exit statements
        # must not skip OpenWrt's service hooks. In particular, refuse an active
        # capture removal before default_prerm can stop the service.
        body += '(\n' + canonical[script].decode().split('\n', 1)[1] + '\n) || exit $?\n'
        if default:
            body += functions + ' ' + default + ' || exit $?\nfi\n'
        return body.encode()

    hooks = {
        'post-install': wrap('postinst', default='default_postinst'),
        'pre-upgrade': wrap('prerm', upgrade=True, default='default_prerm'),
        'post-upgrade': wrap('postinst', upgrade=True, default='default_postinst'),
        'pre-deinstall': wrap('prerm', default='default_prerm'),
    }
    if 'postrm' in canonical:
        hooks['post-deinstall'] = wrap('postrm')
    return hooks


def build(spec, repo_root, out_dir, apk_tool):
    version = spec.version + '-r1'
    output = out_dir / (spec.name + '-' + version + '.apk')
    with tempfile.TemporaryDirectory(prefix='netquota-apk-') as stage:
        stage = Path(stage)
        payload = stage / 'payload'
        payload.mkdir()
        stage_payload(spec, payload)
        command = [apk_tool, 'mkpkg']
        metadata = {'name': spec.name, 'version': version, 'arch': 'noarch',
                    'license': 'GPL-2.0-only', 'url': PROJECT_URL,
                    'description': spec.description, 'maintainer': spec.maintainer,
                    'depends': ' '.join(spec.depends), 'build-time': str(ipk.current_epoch())}
        for key, value in metadata.items():
            command += ['--info', key + ':' + value]
        for name, data in lifecycle_scripts(spec, repo_root).items():
            script = stage / name
            script.write_bytes(data)
            command += ['--script', name + ':' + str(script)]
        command += ['--files', str(payload), '--output', str(output)]
        subprocess.run(command, check=True)
    subprocess.run([apk_tool, 'verify', '--allow-untrusted', str(output)], check=True)
    print('built', output.name, hashlib.sha256(output.read_bytes()).hexdigest())
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk-tool', default=os.environ.get('APK_TOOL', 'apk'))
    parser.add_argument('--output', default='dist')
    parser.add_argument('--version', default=ipk.VERSION_DEFAULT)
    args = parser.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
        parser.error('version must be MAJOR.MINOR.PATCH')
    if not hasattr(os, 'getuid') or os.getuid() != 0:
        parser.error('run with sudo so APK file ownership is root:root')
    ipk.set_epoch(int(os.environ.get('SOURCE_DATE_EPOCH', '0')))
    root = Path(ipk.REPO_ROOT)
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    for spec in ipk.replace_version(ipk.package_specs(str(root)), args.version):
        build(spec, root, output, args.apk_tool)


if __name__ == '__main__':
    main()
