import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / 'tools'))
import build_apk
import build_ipk
import release_metadata


class ReleaseTests(unittest.TestCase):
    def test_apk_frontend_without_postrm_uses_only_declared_hooks(self):
        spec = build_ipk.package_specs(str(ROOT))[1]
        hooks = build_apk.lifecycle_scripts(spec, ROOT)
        self.assertEqual(set(hooks), {'post-install', 'pre-upgrade', 'post-upgrade', 'pre-deinstall'})

    def test_apk_staging_matches_every_ipk_payload_file(self):
        for spec in build_ipk.package_specs(str(ROOT)):
            with self.subTest(package=spec.name), tempfile.TemporaryDirectory() as directory:
                dest = Path(directory)
                build_apk.stage_payload(spec, dest)
                payload = build_ipk.build_data_tar(build_ipk.collect_entries(spec))
                with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
                    for item in archive.getmembers():
                        if item.isfile():
                            actual = dest / item.name.removeprefix('./')
                            self.assertEqual(actual.read_bytes(), archive.extractfile(item).read())
                            if os.name != 'nt':
                                self.assertEqual(actual.stat().st_mode & 0o777, item.mode)
                listing = (dest / ('lib/apk/packages/' + spec.name + '.list')).read_text()
                self.assertIn('/usr/', listing)
                if spec.conffiles:
                    config = dest / 'etc/config/netquota'
                    hashes = (dest / 'lib/apk/packages/netquota.conffiles_static').read_text()
                    self.assertIn('/etc/config/netquota ' + hashlib.sha256(config.read_bytes()).hexdigest(), hashes)

    @unittest.skipUnless(shutil.which('sh'), 'POSIX shell required for lifecycle execution')
    def test_apk_lifecycle_exports_upgrade_state(self):
        spec = build_ipk.package_specs(str(ROOT))[0]
        stubs = {name:b'#!/bin/sh\nprintf "%s" "${PKG_UPGRADE:-0}"\nexit 0\n'
                 for name in ('postinst', 'prerm', 'postrm')}
        with patch.object(build_ipk, '_script_bytes', return_value=stubs):
            hooks = build_apk.lifecycle_scripts(spec, ROOT)
        env = dict(os.environ, IPKG_INSTROOT='', IPKG_NO_SCRIPT='0')
        env.pop('PKG_UPGRADE', None)
        for name, data in hooks.items():
            result = subprocess.run(['sh'], input=data, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, b'1' if 'upgrade' in name else b'0')

    @unittest.skipUnless(shutil.which('sh'), 'POSIX shell required for lifecycle execution')
    def test_apk_cannot_swallow_canonical_hook_failures(self):
        spec = build_ipk.package_specs(str(ROOT))[0]
        stubs = {name:b'#!/bin/sh\nexit 7\n' for name in ('postinst', 'prerm', 'postrm')}
        with patch.object(build_ipk, '_script_bytes', return_value=stubs):
            hooks = build_apk.lifecycle_scripts(spec, ROOT)
        env = dict(os.environ, IPKG_INSTROOT='', IPKG_NO_SCRIPT='0')
        for name, data in hooks.items():
            self.assertEqual(subprocess.run(['sh'], input=data, capture_output=True, env=env).returncode, 7, name)

    @unittest.skipUnless(shutil.which('sh'), 'POSIX shell required for lifecycle execution')
    def test_apk_offline_install_never_executes_device_hooks(self):
        spec = build_ipk.package_specs(str(ROOT))[0]
        hooks = build_apk.lifecycle_scripts(spec, ROOT)
        env = dict(os.environ, IPKG_INSTROOT='/nonexistent-offline-image-root')
        for name, data in hooks.items():
            result = subprocess.run(['sh'], input=data, capture_output=True, env=env)
            self.assertEqual(result.returncode, 0, (name, result.stderr))

    def test_release_versions_agree(self):
        self.assertEqual(release_metadata.version(), build_ipk.VERSION_DEFAULT)

    def test_incomplete_release_cannot_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, GITHUB_REF_TYPE='branch')
            result = subprocess.run([sys.executable, str(ROOT / 'tools/release_metadata.py'),
                                     '--assets', directory], capture_output=True, env=env)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(directory) / 'SHA256SUMS').exists())


if __name__ == '__main__':
    unittest.main()
