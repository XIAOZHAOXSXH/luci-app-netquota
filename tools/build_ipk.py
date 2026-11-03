#!/usr/bin/env python3
"""Deterministic OpenWrt 21.02 IPK builder for NetQuota.

Python standard library only (works on Windows). Builds two packages:

  netquota          0.2.0  arch=all  netquota/files/**            -> /
  luci-app-netquota 0.2.0  arch=all  luci-app-netquota/root/**    -> /
                                     luci-app-netquota/htdocs/**  -> /www/

The repository root is never a source root: docs/, artifacts/, tests/, tools/
and .git must never reach a package payload.

Outer format (verified against real packages, see below):
  gzip(tar) containing, in this order,
      ./debian-binary    (text "2.0\n")
      ./data.tar.gz      (gzip(tar) of the filesystem payload)
      ./control.tar.gz   (gzip(tar) of ./control + maintainer scripts)

Verified samples:
  * GL feed  fw.gl-inet.cn v21.02.3 packages-4.0/aarch64_cortex-a53/glinet
    taskd_1.0.3-1_all.ipk  -> gzip outer (mtime word 0), ./debian-binary,
    ./data.tar.gz, ./control.tar.gz; GNU tar headers, mode "0000644\\0",
    magic "ustar  ", uname/gname "root", uid/gid 0.
  * Vanilla OpenWrt 21.02.3 base/logd_*-aarch64_cortex-a53.ipk -> same layout.
  The ar container is *not* used by either, so this builder emits tar.gz and
  never assumes ar.

Determinism: entry order, mtime (SOURCE_DATE_EPOCH, default 0), uid/gid/owner,
modes and gzip mtime (0) are fixed; member order is sorted; the tar/PAX
format is GNU so the result is independent of the host platform.

Safety: every source path is resolved and must stay inside its declared source
root; symlinks, FIFOs and devices are rejected; only regular files and
directories are packaged. Runtime databases and secrets are never included.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import stat
import sys
import tarfile
from dataclasses import dataclass, field, replace
from typing import Dict, List, Optional, Sequence, Tuple

VERSION_DEFAULT = "0.5.1"
EPOCH_DEFAULT = 0
ARCH_DEFAULT = "all"

# Fixed timestamp used for every tar member and gzip stream (epoch 0).
# Set once per build through set_epoch(); the control field reads the same value.
MTIME_DEFAULT = 0

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --------------------------------------------------------------------------
# Package definitions
# --------------------------------------------------------------------------

# Real, installed package names observed on the target (GL-MT3000, GL 4.11.0,
# OpenWrt 21.02-SNAPSHOT). No virtual/alternatives (no `a|b`) dependencies:
# opkg resolves Depends literally against installed package names.
BACKEND_DEPENDS = [
    "openssl-util",     # local certificate generation and strict key/SAN validation
    "libubox-lua",      # uloop timers and graceful process shutdown
    "lua-cjson",        # strict JSON input and safe-integer output
    "lua",              # /usr/bin/lua interpreter for the CLI, rpcd plugin
    "lsqlite3",         # lua-sqlite3 binding used by the storage layer
    "luci-lib-nixio",   # nixio crypt/io (SHA512-crypt password hashing)
    "luci-lib-jsonc",   # JSON encode/decode for ubus replies
    "libuci-lua",       # UCI config access
    "libubus-lua",      # ubus object registration
    "kmod-nft-core",    # nftables kernel core for the quota table
    # Target-specific: OpenWrt 21.02.3 ships nftables built *with* JSON;
    # the GL 4.11.0 build ships nftables-nojson 0.9.6-3 instead. Declaring the
    # GL package keeps the backend honest on the observed firmware. Re-probe
    # before installing on a GL-MT6000 or any non-4.11.0 firmware.
    "nftables-nojson",
]

FRONTEND_DEPENDS = [
    "luci-base",        # LuCI JS framework (LuCI JS on this build)
    "netquota",         # backend rpcd object is required by the views
]

# Directories whose *files* are installed executable (0755). Anything else is
# 0644. This list is intentionally explicit: it is the union of executable
# locations actually used by this project.
EXECUTABLE_DIRS = (
    "usr/bin",
    "usr/sbin",
    "usr/libexec",
    "usr/libexec/rpcd",
    "etc/init.d",
    "etc/hotplug.d",
    "www/cgi-bin",
    "usr/share/netquota/portal/cgi-bin",
    "usr/share/netquota/redirect/cgi-bin",
)

# Path fragments that must never be packaged from the sources.
FORBIDDEN_BASENAMES = {".git", ".gitignore", ".gitattributes", "dist", "__pycache__",
                       ".pytest_cache", ".env"}


class BuildError(Exception):
    """Raised for any packaging problem; the CLI prints a readable message."""


def set_epoch(epoch: int) -> None:
    """Set the fixed SOURCE_DATE_EPOCH for all subsequent tar/gzip members."""
    global MTIME_DEFAULT
    if epoch < 0:
        raise BuildError("SOURCE_DATE_EPOCH must be >= 0")
    MTIME_DEFAULT = int(epoch)


def current_epoch() -> int:
    return MTIME_DEFAULT


@dataclass(frozen=True)
class PackageSpec:
    name: str
    version: str
    arch: str
    description: str
    depends: List[str]
    # (source_root_relative, install_prefix) pairs. Install prefix "" maps to /.
    roots: List[Tuple[str, str]]
    maintainer: str = "NetQuota maintainers"
    section: str = "net"
    # Optional conffile list (install paths). Only kept when the file exists.
    conffiles: List[str] = field(default_factory=list)
    # Persistent runtime directory owned by the package, if the backend tree
    # actually installs it. postinst may create it with mode 0700 when set.
    rundir: Optional[str] = None
    # Maintainer scripts (basenames under tools/packaging/scripts/<package>/).
    scripts: List[str] = field(default_factory=lambda: ["postinst", "prerm", "postrm"])


# Install destinations whose files carry a fixed executable mode. Read by the
# stdin-driven `install` mode used by the OpenWrt package Makefiles.
INSTALL_EXEC_DIRS = {
    "usr/bin": 0o755,
    "usr/sbin": 0o755,
    "usr/libexec": 0o755,
    "etc/init.d": 0o755,
    "etc/hotplug.d": 0o755,
    "www/cgi-bin": 0o755,
    "usr/share/netquota/portal/cgi-bin": 0o755,
    "usr/share/netquota/redirect/cgi-bin": 0o755,
}


def install_mode_for(install_dir: str) -> int:
    """Return the installed mode for a destination directory like /usr/sbin."""
    d = "/" + install_dir.strip("/")
    for prefix, mode in INSTALL_EXEC_DIRS.items():
        if d == "/" + prefix or d.startswith("/" + prefix + "/"):
            return mode
    return 0o644


def package_specs(repo_root: str) -> List[PackageSpec]:
    """Return the two package specs, with roots resolved against repo_root."""
    return [
        PackageSpec(
            name="netquota",
            version=VERSION_DEFAULT,
            arch=ARCH_DEFAULT,
            description=(
                "Account and shared monthly quota enforcement for OpenWrt "
                "(Lua backend, SQLite storage, nftables). Network capture is "
                "disabled by default (netquota.main.enabled=0); enable it only "
                "after reviewing network readiness and offload settings. "
                "HTTP is the default; HTTPS requires a certificate."
            ),
            depends=list(BACKEND_DEPENDS),
            roots=[(os.path.join(repo_root, "netquota", "files"), "")],
            conffiles=["/etc/config/netquota"],
            rundir=None,
        ),
        PackageSpec(
            name="luci-app-netquota",
            version=VERSION_DEFAULT,
            arch=ARCH_DEFAULT,
            description=(
                "LuCI views for NetQuota account and shared monthly quota "
                "management (requires the netquota backend)."
            ),
            depends=list(FRONTEND_DEPENDS),
            # These are the ONLY frontend source roots. The repository root is
            # deliberately absent: including it would package docs/, artifacts/,
            # tests/, tools/ and .git.
            roots=[
                (os.path.join(repo_root, "luci-app-netquota", "root"), ""),
                (os.path.join(repo_root, "luci-app-netquota", "htdocs"), "www"),
            ],
            scripts=["postinst", "prerm"],
        ),
    ]


# --------------------------------------------------------------------------
# Source collection
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Entry:
    """One installed path to place into data.tar.

    ``install`` is the path relative to / (no leading slash), e.g.
    ``usr/lib/lua/netquota/db.lua``. ``source`` is the absolute host file.
    """

    install: str
    source: Optional[str]     # None for directories
    mode: int
    is_dir: bool


def _is_executable_target(install_rel: str) -> bool:
    if install_rel == 'etc/firewall.netquota':
        return True
    parent = os.path.dirname(install_rel).replace(os.sep, "/")
    for d in EXECUTABLE_DIRS:
        if parent == d or parent.startswith(d + "/"):
            return True
    return False


def _check_no_forbidden_parts(rel_parts: Sequence[str], where: str) -> None:
    for part in rel_parts:
        if part in FORBIDDEN_BASENAMES:
            raise BuildError(
                f"refusing to package forbidden path component {part!r} ({where}); "
                "VCS metadata/dist output must not be packed")
        if part in (".", "..") or part == "":
            raise BuildError(f"unsafe path component {part!r} ({where})")


def _safe_join(root: str, parts: Sequence[str]) -> str:
    """Join ``parts`` under ``root`` and verify containment (no traversal)."""
    _check_no_forbidden_parts(parts, root)
    candidate = os.path.join(root, *parts)
    real_root = os.path.realpath(root)
    real_candidate = os.path.realpath(candidate)
    try:
        common = os.path.commonpath([real_root, real_candidate])
    except ValueError:
        raise BuildError(f"path escapes source root: {candidate}") from None
    if common != real_root:
        raise BuildError(
            f"path escapes source root: {candidate} (root {real_root})")
    if real_candidate == real_root:
        return real_candidate
    # The intermediate directories must not themselves be symlinks.
    probe = root
    for part in parts[:-1]:
        probe = os.path.join(probe, part)
        if os.path.islink(probe):
            raise BuildError(
                f"symlinked directory in install path is refused: {probe}")
    return candidate


def collect_entries(spec: PackageSpec) -> List[Entry]:
    """Walk every source root of ``spec`` and return sorted installed entries."""
    by_install: Dict[str, Entry] = {}
    allowed_roots = [os.path.realpath(r) for r, _ in spec.roots]

    for root, prefix in spec.roots:
        real_root = os.path.realpath(root)
        if not os.path.isdir(real_root):
            # Root not created yet (concurrent backend/frontend work): empty.
            continue
        for dirpath, dirnames, filenames in os.walk(real_root, followlinks=False):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, real_root)
            rel_parts = [] if rel_dir == "." else rel_dir.split(os.sep)
            _check_no_forbidden_parts(rel_parts, dirpath)

            # Directories, including those the walk will visit.
            for d in list(dirnames):
                full = os.path.join(dirpath, d)
                if os.path.islink(full):
                    raise BuildError(f"refusing symlinked directory: {full}")
                if d in FORBIDDEN_BASENAMES:
                    dirnames.remove(d)
                    continue
                sub_rel = rel_parts + [d]
                install = _install_path(prefix, sub_rel, is_dir=True)
                by_install.setdefault(
                    install, Entry(install=install, source=None,
                                   mode=0o755, is_dir=True))

            for f in sorted(filenames):
                full = os.path.join(dirpath, f)
                # Validate containment against the owning root.
                _safe_join(root, rel_parts + [f])
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    raise BuildError(
                        f"refusing symlinked file: {full} -> "
                        f"{os.readlink(full)}")
                if not stat.S_ISREG(st.st_mode):
                    raise BuildError(
                        f"refusing non-regular file: {full} "
                        f"(mode {stat.filemode(st.st_mode)})")
                if f in FORBIDDEN_BASENAMES:
                    continue
                rel_file = rel_parts + [f]
                _check_no_forbidden_parts(rel_file, full)
                install = _install_path(prefix, rel_file, is_dir=False)
                if install in by_install and not by_install[install].is_dir:
                    raise BuildError(
                        f"duplicate install path {install!r}: "
                        f"{by_install[install].source} and {full}")
                mode = 0o755 if _is_executable_target(install) else 0o644
                by_install[install] = Entry(
                    install=install, source=full, mode=mode, is_dir=False)

    # Any installed file implies its parent dirs; add missing ones.
    for inst in list(by_install):
        parts = inst.split("/")
        for i in range(1, len(parts)):
            parent = "/".join(parts[:i])
            if not parent:
                continue
            by_install.setdefault(
                parent, Entry(install=parent, source=None,
                              mode=0o755, is_dir=True))

    entries = list(by_install.values())
    # Reject roots that are not inside one of the declared source roots
    # (defence in depth for future root additions).
    for e in entries:
        if e.source is not None:
            real = os.path.realpath(e.source)
            if not any(real.startswith(r + os.sep) or real == r
                       for r in allowed_roots):
                raise BuildError(
                    f"source outside declared roots: {e.source}")

    entries.sort(key=lambda e: e.install)
    return entries


def _install_path(prefix: str, parts: Sequence[str], is_dir: bool) -> str:
    joined = "/".join(parts)
    if prefix:
        return f"{prefix.rstrip('/')}/{joined}" if joined else prefix.rstrip("/")
    return joined


def installed_size_kib(entries: Sequence[Entry]) -> int:
    """Installed-Size in KiB (1024-byte blocks), per OpenWrt opkg semantics.

    Counts regular-file bytes only and rounds up, matching what `du -k` style
    accounting reports for the payload.
    """
    total = 0
    for e in entries:
        if e.is_dir or e.source is None:
            continue
        total += os.path.getsize(e.source)
    if total == 0:
        return 0
    return max(1, (total + 1023) // 1024)


# --------------------------------------------------------------------------
# Maintainer scripts and conffiles
# --------------------------------------------------------------------------

def scripts_dir(repo_root: str, package: str) -> str:
    """Canonical maintainer-script source shared by build_ipk.py and Makefiles.

    The OpenWrt package Makefiles copy from exactly these paths, so the Python
    builder and the feed build cannot drift.
    """
    return os.path.join(repo_root, "tools", "packaging", "scripts", package)


def _read_script_text(path: str) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read()
    # Maintainer scripts must be LF-only POSIX shell.
    text = raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    if not text.startswith(b"#!"):
        raise BuildError(f"maintainer script lacks shebang: {path}")
    return text


def _script_bytes(repo_root: str, spec: PackageSpec) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    base = scripts_dir(repo_root, spec.name)
    for name in spec.scripts:
        path = os.path.join(base, name)
        if not os.path.isfile(path):
            raise BuildError(
                f"missing maintainer script {name} for {spec.name}: {path}")
        out[name] = _read_script_text(path)
    return out


def _conffiles(entries: Sequence[Entry], spec: PackageSpec) -> List[str]:
    installed = {"/" + e.install for e in entries if not e.is_dir}
    return [p for p in spec.conffiles if p in installed]


def control_fields(spec: PackageSpec, entries: Sequence[Entry],
                   conffiles: Sequence[str]) -> List[Tuple[str, str]]:
    """Return control fields in deterministic order.

    Conffiles is deliberately NOT a field here: it is emitted as its own
    ``./conffiles`` member by :func:`build_control_tar`, which is the form both
    the OpenWrt build system and opkg consume.
    """
    return [
        ("Package", spec.name),
        ("Version", spec.version),
        ("Depends", ", ".join(spec.depends)),
        ("Source", "netquota"),
        ("SourceName", spec.name),
        ("Section", spec.section),
        ("SourceDateEpoch", str(current_epoch())),
        ("Maintainer", spec.maintainer),
        ("Architecture", spec.arch),
        ("Installed-Size", str(installed_size_kib(entries))),
        ("Description", spec.description.replace("\n", " ")),
    ]


def control_text(spec: PackageSpec, entries: Sequence[Entry],
                 conffiles: Sequence[str]) -> bytes:
    lines = [f"{k}: {v}" for k, v in control_fields(spec, entries, conffiles)]
    return ("\n".join(lines) + "\n").encode("utf-8")


# --------------------------------------------------------------------------
# Tar construction (GNU tar format, mirrored from observed samples)
# --------------------------------------------------------------------------

def _tar_add_bytes(tar: tarfile.TarFile, name: str, data: bytes,
                   mode: int = 0o644, mtime: Optional[int] = None) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = mode
    info.mtime = current_epoch() if mtime is None else mtime
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.type = tarfile.REGTYPE
    tar.addfile(info, io.BytesIO(data))


def _tar_add_dir(tar: tarfile.TarFile, name: str,
                 mtime: Optional[int] = None) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = 0
    info.mode = 0o755
    info.mtime = current_epoch() if mtime is None else mtime
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.type = tarfile.DIRTYPE
    tar.addfile(info)


def _gzip_bytes(payload: bytes) -> bytes:
    # mtime=0 and no filename -> byte-identical gzip on every platform.
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0,
                       compresslevel=9) as gz:
        gz.write(payload)
    return buf.getvalue()


def _new_tar(stream: io.BytesIO) -> tarfile.TarFile:
    return tarfile.open(fileobj=stream, mode="w", format=tarfile.GNU_FORMAT)


def build_data_tar(entries: Sequence[Entry]) -> bytes:
    buf = io.BytesIO()
    with _new_tar(buf) as tar:
        _tar_add_dir(tar, "./")
        # Directories first (sorted), then files (sorted) - stable and matches
        # the order produced by the OpenWrt ipkg generator closely enough for
        # opkg, while remaining fully deterministic.
        for e in entries:
            if e.is_dir:
                _tar_add_dir(tar, f"./{e.install}/")
        for e in entries:
            if e.is_dir or e.source is None:
                continue
            with open(e.source, "rb") as fh:
                data = fh.read()
            if e.mode == 0o755 and data.startswith(b"#!"):
                data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
            if (e.install.endswith((".db", ".db-wal", ".db-shm", ".key"))
                    or b"PRIVATE KEY-----" in data):
                raise BuildError(f"refusing runtime database/private key: {e.install}")
            _tar_add_bytes(tar, f"./{e.install}", data, mode=e.mode)
    return buf.getvalue()


def build_control_tar(spec: PackageSpec, control: bytes,
                      scripts: Dict[str, bytes],
                      conffiles: Sequence[str] = ()) -> bytes:
    buf = io.BytesIO()
    with _new_tar(buf) as tar:
        _tar_add_dir(tar, "./")
        _tar_add_bytes(tar, "./control", control, mode=0o644)
        if conffiles:
            # OpenWrt/opkg conffile list: one absolute path per line.
            listing = ("\n".join(conffiles) + "\n").encode("utf-8")
            _tar_add_bytes(tar, "./conffiles", listing, mode=0o644)
        for name in sorted(scripts):
            # POSIX shell scripts are 0755 and LF-only.
            _tar_add_bytes(tar, f"./{name}", scripts[name], mode=0o755)
    return buf.getvalue()


def build_ipk(spec: PackageSpec, repo_root: str,
              out_dir: str) -> Dict[str, object]:
    """Assemble one .ipk; returns a result dictionary with facts."""
    entries = collect_entries(spec)
    if not any(not e.is_dir for e in entries):
        raise BuildError(
            f"{spec.name}: no files found under " +
            ", ".join(os.path.relpath(r, repo_root) for r, _ in spec.roots) +
            " (is the tree checked out?)")
    if spec.rundir is not None:
        rundir_rel = spec.rundir.strip("/")
        if not any(e.is_dir and e.install == rundir_rel for e in entries):
            raise BuildError(
                f"{spec.name}: rundir {spec.rundir} is not installed by the "
                "source tree; refusing to create it from postinst")
    conffiles = _conffiles(entries, spec)
    scripts = _script_bytes(repo_root, spec)

    data_tar_gz = _gzip_bytes(build_data_tar(entries))
    # The observed OpenWrt/GL samples store compressed data archive bytes here.
    fields = control_fields(spec, entries, conffiles)
    fields = [(key, str(len(data_tar_gz)) if key == "Installed-Size" else value)
              for key, value in fields]
    control = ("\n".join(f"{key}: {value}" for key, value in fields) + "\n").encode("utf-8")
    control_tar_gz = _gzip_bytes(build_control_tar(spec, control, scripts,
                                                   conffiles))

    outer = io.BytesIO()
    with _new_tar(outer) as tar:
        _tar_add_bytes(tar, "./debian-binary", b"2.0\n")
        _tar_add_bytes(tar, "./data.tar.gz", data_tar_gz)
        _tar_add_bytes(tar, "./control.tar.gz", control_tar_gz)
    ipk = _gzip_bytes(outer.getvalue())

    os.makedirs(out_dir, exist_ok=True)
    filename = f"{spec.name}_{spec.version}_{spec.arch}.ipk"
    path = os.path.join(out_dir, filename)
    tmp = path + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(ipk)
    os.replace(tmp, path)

    return {
        "package": spec.name,
        "version": spec.version,
        "arch": spec.arch,
        "path": path,
        "filename": filename,
        "bytes": len(ipk),
        "sha256": hashlib.sha256(ipk).hexdigest(),
        "file_count": sum(1 for e in entries if not e.is_dir),
        "dir_count": sum(1 for e in entries if e.is_dir),
        "installed_size_kib": installed_size_kib(entries),
        "conffiles": conffiles,
        "scripts": sorted(scripts),
        "executable_paths": [e.install for e in entries
                             if not e.is_dir and e.mode == 0o755],
    }


# --------------------------------------------------------------------------
# dist manifest
# --------------------------------------------------------------------------

def write_manifest(out_dir: str, results: Sequence[Dict[str, object]],
                   version: str, epoch: int) -> Tuple[str, str]:
    lines = [
        "# NetQuota IPK build manifest",
        f"version: {version}",
        f"architecture: {ARCH_DEFAULT}",
        f"source_date_epoch: {epoch}",
        "",
    ]
    for r in sorted(results, key=lambda d: str(d["package"])):
        lines.append(f"package: {r['package']}")
        lines.append(f"  file: {r['filename']}")
        lines.append(f"  bytes: {r['bytes']}")
        lines.append(f"  sha256: {r['sha256']}")
        lines.append(f"  files: {r['file_count']}  dirs: {r['dir_count']}")
        lines.append(f"  installed_size_kib: {r['installed_size_kib']}")
        lines.append(f"  conffiles: {' '.join(r['conffiles']) or '-'}")
    manifest_path = os.path.join(out_dir, "MANIFEST.txt")
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")

    sums = [f"{r['sha256']}  {r['filename']}"
            for r in sorted(results, key=lambda d: str(d["filename"]))]
    sums_path = os.path.join(out_dir, "SHA256SUMS")
    with open(sums_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(sums) + "\n")
    return manifest_path, sums_path


def replace_version(specs: Sequence[PackageSpec],
                    version: str) -> List[PackageSpec]:
    """Return the specs with the requested version applied (frozen dataclass)."""
    out: List[PackageSpec] = []
    for spec in specs:
        out.append(replace(spec, version=version))
    return out


# --------------------------------------------------------------------------
# Staging mode for OpenWrt package Makefiles
# --------------------------------------------------------------------------

def install_lines(package_root: str, install_dir: str, prefix: str) -> List[str]:
    """Return ``source|destination`` lines for one Package/<pkg>/install block.

    This is the single staging implementation shared by the Python builder and
    the OpenWrt recipes, so the feed build and the local build cannot diverge
    on paths, normalization or modes.
    """
    prefix = "/" + prefix.strip("/") if prefix.strip("/") else "/"
    real_root = os.path.realpath(package_root)
    if os.path.islink(package_root):
        raise BuildError(f"source root is a symlink: {package_root}")
    if not os.path.isdir(real_root):
        raise BuildError(f"source root is not a directory: {package_root}")
    install_dir = install_dir.rstrip("/") or "/"
    lines: List[str] = []
    for dirpath, dirnames, filenames in os.walk(real_root, followlinks=False):
        dirnames.sort()
        rel_dir = os.path.relpath(dirpath, real_root)
        rel_parts = [] if rel_dir == "." else rel_dir.split(os.sep)
        _check_no_forbidden_parts(rel_parts, dirpath)
        for d in list(dirnames):
            if d in FORBIDDEN_BASENAMES:
                dirnames.remove(d)
        for f in sorted(filenames):
            full = os.path.join(dirpath, f)
            _safe_join(real_root, rel_parts + [f])
            st = os.lstat(full)
            if stat.S_ISLNK(st.st_mode):
                raise BuildError(f"refusing symlinked file: {full}")
            if not stat.S_ISREG(st.st_mode):
                raise BuildError(f"refusing non-regular file: {full}")
            if f in FORBIDDEN_BASENAMES:
                continue
            rel = rel_parts + [f]
            _check_no_forbidden_parts(rel, full)
            dest_dir = prefix if prefix == "/" else prefix + "/"
            dest_dir += "/".join(rel_parts)
            if not dest_dir.endswith("/"):
                dest_dir += "/"
            if dest_dir == "//":
                dest_dir = "/"
            dest = dest_dir + f
            dest = "/" + dest.strip("/")
            lines.append(f"{full}|{dest}")
    return lines


def run_install_mode(lines: Sequence[str], dest_root: str) -> int:
    """Copy ``source|destination`` lines into ``dest_root`` with fixed modes."""
    dest_root = os.path.abspath(dest_root)
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.count("|") != 1:
            raise BuildError(f"malformed install line (need one '|'): {line}")
        src, dest = line.split("|")
        if not dest.startswith("/"):
            raise BuildError(f"destination must be absolute: {dest}")
        rel = dest.lstrip("/")
        _check_no_forbidden_parts(rel.split("/"), dest)
        target = os.path.join(dest_root, *rel.split("/"))
        real_target = os.path.realpath(os.path.dirname(target))
        if not (real_target == os.path.realpath(dest_root)
                or real_target.startswith(os.path.realpath(dest_root) + os.sep)):
            raise BuildError(f"destination escapes staging root: {dest}")
        with open(src, "rb") as fh:
            data = fh.read()
        # Installed executable scripts must be LF-only.
        if "/etc/init.d/" in dest or "/usr/libexec/" in dest or dest.startswith("/usr/sbin/"):
            data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(data)
        os.chmod(target, install_mode_for(os.path.dirname(dest)))
        print(dest)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build deterministic NetQuota OpenWrt 21.02 IPK packages.")
    parser.add_argument("--version", default=VERSION_DEFAULT,
                        help=f"package version (default {VERSION_DEFAULT})")
    parser.add_argument("--output", default=os.path.join(REPO_ROOT, "dist"),
                        help="output directory (default <repo>/dist)")
    parser.add_argument("--epoch", type=int, default=os.environ.get("SOURCE_DATE_EPOCH", EPOCH_DEFAULT),
                        help="SOURCE_DATE_EPOCH applied to tar/gzip mtimes "
                             f"(default {EPOCH_DEFAULT}; fixed for reproducible "
                             "output)")
    parser.add_argument("--package", action="append", choices=[
        "netquota", "luci-app-netquota"],
        help="build only the named package (repeatable; default: both)")
    # Staging mode used by the OpenWrt package Makefiles.
    parser.add_argument("--mode", choices=["build", "install"], default="build",
                        help="build .ipk files, or stage 'src|dest' lines from "
                             "stdin into --dest-root")
    parser.add_argument("--src", help="install mode: source root directory")
    parser.add_argument("--dir", help="install mode: destination directory, "
                                      "e.g. /usr/lib/lua/netquota")
    parser.add_argument("--prefix", default="/",
                        help="install mode: prefix applied before --dir")
    parser.add_argument("--dest-root", help="install mode: staging root")
    parser.add_argument("--repo-root", default=REPO_ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.epoch < 0:
        print("error: --epoch must be >= 0", file=sys.stderr)
        return 2
    if not args.version or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.+~_-" for c in args.version) or args.version in (".", ".."):
        print("error: invalid package version", file=sys.stderr)
        return 2
    set_epoch(args.epoch)

    if args.mode == "install":
        missing = [n for n in ("src", "dir", "dest_root") if not getattr(args, n)]
        if missing:
            print("error: --mode install requires " +
                  ", ".join("--" + m.replace("_", "-") for m in missing),
                  file=sys.stderr)
            return 2
        lines = sys.stdin.read().splitlines()
        try:
            generated = install_lines(args.src, args.dir, args.prefix)
            if lines:
                generated.extend(lines)
            return run_install_mode(generated, args.dest_root)
        except BuildError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    repo_root = os.path.abspath(args.repo_root)
    out_dir = os.path.abspath(args.output)

    try:
        specs = package_specs(repo_root)
        if args.package:
            selected = set(args.package)
            specs = [s for s in specs if s.name in selected]
        results = []
        for spec in replace_version(specs, args.version):
            result = build_ipk(spec, repo_root, out_dir)
            results.append(result)
            print(f"built {result['filename']}  "
                  f"{result['bytes']} bytes  "
                  f"{result['file_count']} files "
                  f"({result['installed_size_kib']} KiB installed)")
            print(f"  sha256 {result['sha256']}")
            if result["executable_paths"]:
                print("  exec   " + " ".join(result["executable_paths"]))
            if result["conffiles"]:
                print("  conffile " + " ".join(result["conffiles"]))
        manifest_path, sums_path = write_manifest(out_dir, results,
                                                  args.version, args.epoch)
        print(f"manifest {manifest_path}")
        print(f"sums     {sums_path}")
        return 0
    except BuildError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: I/O failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
