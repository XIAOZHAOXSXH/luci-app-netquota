#!/usr/bin/env python3
"""Packaging contract tests for tools/build_ipk.py.

Each test builds an isolated fixture repo tree in a TemporaryDirectory and
invokes the real builder by absolute repo path with --repo-root <fixture>.
The developer machine and the working tree's tools/ are never modified.
"""
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILDER = os.path.join(REPO_ROOT, "tools", "build_ipk.py")
SCRIPTS_DIR = os.path.join(REPO_ROOT, "tools", "packaging", "scripts")

BACKEND = "netquota"
FRONTEND = "luci-app-netquota"
MAINTAINER_SCRIPTS = {
    "netquota": ("postinst", "prerm", "postrm"),
    "luci-app-netquota": ("postinst", "prerm"),
}
PRIVATE_KEY_MARKER = "-----BEGIN RSA PRIVATE KEY-----"


def write(path, data, mode=0o644):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if isinstance(data, str):
        data = data.encode("utf-8")
    with open(path, "wb") as handle:
        handle.write(data)
    os.chmod(path, mode)


def load_scripts():
    """Load canonical maintainer scripts from the repo, or None if absent."""
    scripts = {}
    for pkg, names in MAINTAINER_SCRIPTS.items():
        for name in names:
            src = os.path.join(SCRIPTS_DIR, pkg, name)
            if os.path.isfile(src):
                with open(src, "rb") as handle:
                    scripts["%s/%s" % (pkg, name)] = handle.read()
    return scripts


def build_fixture(root, scripts):
    """Create a minimal but contract-complete repository tree."""
    pkg_root = os.path.join(root, BACKEND)
    write(os.path.join(pkg_root, "files", "etc", "config", "netquota"),
          "# netquota\nconfig netquota 'main'\n\toption enabled '0'\n\n"
          "config backend 'main'\n\toption type 'nftables'\n")
    write(os.path.join(pkg_root, "files", "usr", "sbin", "netquota"),
          "#!/bin/sh\r\nexec /usr/bin/lua /usr/lib/netquota/main.lua \"$@\"\r\n",
          mode=0o755)
    write(os.path.join(pkg_root, 'files', 'etc', 'firewall.netquota'), '#!/bin/sh\nexit 0\n')

    front = os.path.join(root, FRONTEND)
    write(os.path.join(front, "htdocs", "luci-static", "resources", "netquota",
                       "netquota.js"),
          "/* netquota overview */\r\nvar netquotaView = {};\n")
    write(os.path.join(front, "htdocs", "luci-static", "resources", "netquota",
                       "netquota.css"), "body{color:#000}\n")
    write(os.path.join(front, "root", "usr", "share", "rpc", "acl.d",
                       "luci-app-netquota.json"),
          json.dumps({"luci-app-netquota": {"description": "netquota",
                                            "read": {"ubus": {"netquota": ["status"]}}}},
                     indent=2) + "\n")

    for rel in ("portal", "redirect"):
        write(os.path.join(pkg_root, "files", "usr", "share", "netquota", rel,
                           "cgi-bin", "api"),
              "#!/bin/sh\r\nexec /usr/bin/lua /usr/lib/netquota/cgi.lua\r\n",
              mode=0o755)

    for key, data in scripts.items():
        pkg, name = key.split("/")
        write(os.path.join(root, "tools", "packaging", "scripts", pkg, name), data,
              mode=0o755)

    # Unrelated content that must never reach a payload.
    write(os.path.join(root, ".git", "config"), "[core]\n\trepositoryformatversion = 0\n", 0o600)
    write(os.path.join(root, "docs", "README.md"), "docs\n")
    write(os.path.join(root, "artifacts", "leak.txt"), "artifacts\n")
    write(os.path.join(root, "tests", "leak.txt"), "tests\n")
    write(os.path.join(root, "tools", "leak.txt"), "tools\n")
    return root


def add_database_files(root):
    pkg_root = os.path.join(root, BACKEND, "files", "etc", "config")
    write(os.path.join(pkg_root, "state.db"), "SQLite format 3\n")
    write(os.path.join(pkg_root, "state.db-wal"), "wal\n")


def add_private_key(root):
    write(os.path.join(root, BACKEND, "files", "etc", "secret.pem"),
          PRIVATE_KEY_MARKER + "\nAAAA\n")


def run_builder(root, out, *extra, env=None):
    cmd = [sys.executable, BUILDER, "--repo-root", root, "--output", out,
           "--version", "0.1.0"]
    cmd.extend(extra)
    clean = dict(os.environ)
    clean.pop("SOURCE_DATE_EPOCH", None)
    clean.update(env or {})
    return subprocess.run(cmd, capture_output=True, text=True, env=clean)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_tar(raw):
    """Return {name: (member, bytes)} for a gzip-compressed tar blob."""
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        out = {}
        for member in tar.getmembers():
            data = None
            if member.isfile():
                data = tar.extractfile(member).read()
            out[norm(member.name)] = (member, data)
        return out


def norm(name):
    return name[2:] if name.startswith("./") else name


def gzip_header_mtime(raw):
    return int.from_bytes(raw[4:8], "little")


class PackagingContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not os.path.isfile(BUILDER):
            raise unittest.SkipTest("tools/build_ipk.py not available yet")
        cls.scripts = load_scripts()
        if not cls.scripts:
            raise unittest.SkipTest("canonical maintainer scripts not available yet")

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = self._tmp.name
        self.root = build_fixture(os.path.join(self.tmp, "repo"), self.scripts)

    def tearDown(self):
        self._tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def build(self, name="out", *extra, env=None):
        out = os.path.join(self.tmp, name)
        os.makedirs(out, exist_ok=True)
        proc = run_builder(self.root, out, *extra, env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return out, proc

    def open_ipk(self, path):
        raw_members = {}
        with tarfile.open(path, mode="r:gz") as outer:
            names = sorted(norm(m.name) for m in outer.getmembers())
            self.assertEqual(names, ["control.tar.gz", "data.tar.gz", "debian-binary"])
            for member in outer.getmembers():
                raw_members[norm(member.name)] = outer.extractfile(member).read()
        ctl_raw = raw_members["control.tar.gz"]
        data_raw = raw_members["data.tar.gz"]
        return raw_members["debian-binary"], read_tar(ctl_raw), read_tar(data_raw), data_raw

    def ipk_path(self, out, pkg):
        path = os.path.join(out, "%s_0.1.0_all.ipk" % pkg)
        self.assertTrue(os.path.isfile(path), path)
        return path

    def control_fields(self, control):
        fields = {}
        for line in control["control"][1].decode().splitlines():
            if ":" in line:
                key, value = line.split(":", 1)
                fields[key.strip()] = value.strip()
        return fields

    # -- tests -----------------------------------------------------------
    def test_deterministic_rebuild(self):
        out_a, _ = self.build("a")
        out_b, _ = self.build("b")
        for pkg in (BACKEND, FRONTEND):
            pa, pb = self.ipk_path(out_a, pkg), self.ipk_path(out_b, pkg)
            self.assertEqual(sha256(pa), sha256(pb), pkg)
        sums_a = os.path.join(out_a, "SHA256SUMS")
        sums_b = os.path.join(out_b, "SHA256SUMS")
        self.assertTrue(os.path.isfile(sums_a))
        with open(sums_a) as fa, open(sums_b) as fb:
            self.assertEqual(fa.read(), fb.read())

    def test_backend_payload_layout(self):
        out, _ = self.build()
        debian, control, data, data_raw = self.open_ipk(self.ipk_path(out, BACKEND))
        self.assertEqual(debian, b"2.0\n")
        paths = {norm(n) for n in data}
        for expected in ("etc/config/netquota", "usr/sbin/netquota",
                         "usr/share/netquota/portal/cgi-bin/api",
                         "usr/share/netquota/redirect/cgi-bin/api"):
            self.assertIn(expected, paths)
        self.assertNotIn("luci-static", " ".join(paths))
        self.assertNotIn("usr/share/rpc", " ".join(paths))
        # Conffile declaration.
        conff = control.get("./conffiles") or control.get("conffiles")
        self.assertIsNotNone(conff, sorted(control))
        self.assertIn(b"etc/config/netquota", conff[1])
        # Maintainer scripts present and executable.
        for name in ("postinst", "prerm", "postrm"):
            key = "./" + name if "./" + name in control else name
            self.assertIn(key, control, sorted(control))
            self.assertTrue(control[key][0].mode & stat.S_IXUSR, name)
        # Metadata.
        fields = self.control_fields(control)
        self.assertEqual(fields["Package"], BACKEND)
        self.assertEqual(fields["Architecture"], "all")
        self.assertEqual(fields["Version"], "0.1.0")
        self.assertIn("Depends", fields)
        self.assertEqual(int(fields["Installed-Size"]), len(data_raw))
        # Payload hygiene.
        joined = " ".join(paths)
        for bad in (".db", ".db-wal", ".key", ".git", "docs/", "artifacts/",
                    "tests/", "tools/"):
            self.assertNotIn(bad, joined)

    def test_frontend_payload_layout(self):
        out, _ = self.build()
        _, control, data, data_raw = self.open_ipk(self.ipk_path(out, FRONTEND))
        paths = {norm(n) for n in data}
        self.assertIn("www/luci-static/resources/netquota/netquota.js", paths)
        self.assertIn("usr/share/rpc/acl.d/luci-app-netquota.json", paths)
        self.assertNotIn("etc/config/netquota", paths)
        js = data["www/luci-static/resources/netquota/netquota.js"][0]
        self.assertEqual(js.mode & 0o777, 0o644)
        css = data["www/luci-static/resources/netquota/netquota.css"][0]
        self.assertEqual(css.mode & 0o777, 0o644)
        fields = self.control_fields(control)
        self.assertEqual(fields["Package"], FRONTEND)
        self.assertEqual(fields["Architecture"], "all")
        self.assertEqual(int(fields["Installed-Size"]), len(data_raw))

    def test_tar_metadata_and_line_endings(self):
        out, _ = self.build()
        for pkg in (BACKEND, FRONTEND):
            _, control, data, _ = self.open_ipk(self.ipk_path(out, pkg))
            for label, entries in (("control", control), ("data", data)):
                for name, (member, _) in entries.items():
                    if norm(name) in ("control", "conffiles"):
                        continue
                    self.assertEqual(member.uid, 0, "%s %s uid" % (label, name))
                    self.assertEqual(member.gid, 0, "%s %s gid" % (label, name))
                    self.assertEqual(member.uname, "root", "%s %s uname" % (label, name))
                    self.assertEqual(member.gname, "root", "%s %s gname" % (label, name))
                    self.assertEqual(member.mtime, 0, "%s %s mtime" % (label, name))
        # Shell scripts must be LF and 0755, including CRLF fixture sources.
        for pkg in (BACKEND, FRONTEND):
            _, control, data, _ = self.open_ipk(self.ipk_path(out, pkg))
            entries = list(control.values()) + list(data.values())
            for member, blob in entries:
                if blob is None or not blob.startswith(b"#!"):
                    continue
                self.assertNotIn(b"\r\n", blob, member.name)
                self.assertTrue(member.mode & 0o111, member.name)
                self.assertEqual(member.mode & 0o777, 0o755, member.name)

    def test_epoch_sets_all_mtimes(self):
        out, _ = self.build("epoch", "--epoch", "123")
        for pkg in (BACKEND, FRONTEND):
            path = self.ipk_path(out, pkg)
            with tarfile.open(path, mode="r:gz") as outer:
                for member in outer.getmembers():
                    raw = outer.extractfile(member).read()
                    header = norm(member.name)
                    if header in ("data.tar.gz", "control.tar.gz"):
                        self.assertEqual(gzip_header_mtime(raw), 0,
                                         "%s gzip mtime" % header)
                        tar = read_tar(raw)
                        for inner in tar.values():
                            self.assertEqual(inner[0].mtime, 123, inner[0].name)
                    elif header != "debian-binary":
                        self.assertEqual(member.mtime, 123, header)

    def test_source_date_epoch_env_honored(self):
        out, _ = self.build("sde", env={"SOURCE_DATE_EPOCH": "777"})
        _, control, data, _ = self.open_ipk(self.ipk_path(out, BACKEND))
        for member, _ in list(control.values()) + list(data.values()):
            if norm(member.name) in ("control", "conffiles"):
                continue
            self.assertEqual(member.mtime, 777, member.name)

    def test_private_key_rejected(self):
        add_private_key(self.root)
        out = os.path.join(self.tmp, "reject")
        proc = run_builder(self.root, out)
        self.assertNotEqual(proc.returncode, 0, "PRIVATE KEY material accepted")
        for pkg in (BACKEND, FRONTEND):
            path = os.path.join(out, "%s_0.1.0_all.ipk" % pkg)
            self.assertFalse(os.path.isfile(path), path)

    def test_database_files_rejected(self):
        add_database_files(self.root)
        out = os.path.join(self.tmp, "rejectdb")
        proc = run_builder(self.root, out)
        self.assertNotEqual(proc.returncode, 0, "database files accepted")
        for pkg in (BACKEND, FRONTEND):
            path = os.path.join(out, "%s_0.1.0_all.ipk" % pkg)
            self.assertFalse(os.path.isfile(path), path)

    def test_unsafe_version_rejected(self):
        out = os.path.join(self.tmp, "unsafe")
        proc = run_builder(self.root, out, "--version", "../../escape")
        self.assertNotEqual(proc.returncode, 0)
        found = []
        if os.path.isdir(out):
            found = [n for n in os.listdir(out) if n.endswith(".ipk")]
        self.assertEqual(found, [])
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "escape")))

    def test_symlink_source_rejected(self):
        target = os.path.join(self.root, BACKEND, "files", "etc", "config", "netquota")
        link = os.path.join(self.root, BACKEND, "files", "etc", "config", "link.conf")
        try:
            os.symlink(target, link)
        except (OSError, NotImplementedError, AttributeError):
            self.skipTest("local filesystem does not allow symlink creation")
        out = os.path.join(self.tmp, "symlink")
        proc = run_builder(self.root, out)
        self.assertNotEqual(proc.returncode, 0, "symlink source accepted")

    def test_module_compiles(self):
        proc = subprocess.run(
            [sys.executable, "-m", "py_compile", __file__],
            capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


if __name__ == "__main__":
    unittest.main()
