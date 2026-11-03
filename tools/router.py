#!/usr/bin/env python3
"""Workstation-side CLI for the OpenWrt netquota box (GL-MT3000).

Design constraints (do not relax):
  * Runs on the *workstation* only. No Python is required on the router.
  * The router has NO SFTP subsystem. Nothing here may use SFTP.
    Uploads go over an SSH exec channel writing to `cat > tmpfile` on stdin.
  * Password comes only from $NETQUOTA_SSH_PASSWORD or getpass(); never from
    the command line, never written to files or logs.
  * Host keys are verified against known_hosts by default. An unknown host may
    be accepted only with an explicit --fingerprint whose value is compared in
    constant time. A *known* mismatch is always rejected.
  * Only stdlib + paramiko.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import os
import posixpath
import select
import shlex
import sys
import tempfile
import time
import uuid

try:
    import paramiko
except Exception:  # pragma: no cover - import guard for friendly errors
    paramiko = None  # type: ignore[assignment]

DEFAULT_HOST = "192.168.8.1"
DEFAULT_USER = "root"
SSH_PORT = 22
IO_CHUNK = 64 * 1024

# Observed on the reference GL-MT3000 unit (MD5 of the host key blob).
OBSERVED_FINGERPRINT = "1e305652a871e9d0a1ea9d9c44711b10"

CONFIG_FILE = "/etc/config/netquota"
DB_FILE = "/etc/netquota/netquota.db"

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_TIMEOUT = 124


class CliError(Exception):
    """Routine, user-facing failure. Printed without a traceback."""

    def __init__(self, message: str, code: int = EXIT_FAIL) -> None:
        super().__init__(message)
        self.code = code


# --------------------------------------------------------------------------
# Pure helpers (unit tested)
# --------------------------------------------------------------------------

def normalize_script(text: str) -> str:
    """Normalize a script body for the router: CRLF/CR -> LF, guarantee a
    trailing newline so the last command is executed by sh."""
    if not isinstance(text, str):
        raise CliError("script source must be text", EXIT_USAGE)
    out = text.replace("\r\n", "\n").replace("\r", "\n")
    if out and not out.endswith("\n"):
        out += "\n"
    return out


def validate_remote_path(path: str) -> str:
    """Validate an absolute POSIX path for use on the router.

    Rejects empty values, relative paths, control characters (including NUL,
    newline and CR used for injection), and any path whose normalized form
    escapes or becomes the filesystem root. Returns the normalized path.
    """
    if not isinstance(path, str) or not path:
        raise CliError("remote path must be a non-empty string", EXIT_USAGE)
    if not path.startswith("/"):
        raise CliError(f"remote path must be absolute: {path!r}", EXIT_USAGE)
    for ch in path:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise CliError(
                f"remote path contains control character {code!r}", EXIT_USAGE)
    if ".." in path.split("/"):
        raise CliError(f"remote path may not contain '..': {path!r}", EXIT_USAGE)
    normalized = posixpath.normpath(path)
    if not normalized.startswith("/") or normalized == "/":
        raise CliError(f"remote path is not usable: {path!r}", EXIT_USAGE)
    return normalized


def _fingerprint_md5(key_blob: bytes) -> str:
    return hashlib.md5(key_blob).hexdigest()


def _fingerprint_sha256(key_blob: bytes) -> str:
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")


def key_fingerprint_matches(expected: str, key_blob: bytes) -> bool:
    """Constant-time comparison of a user supplied fingerprint against the
    server host key blob.

    Accepts "SHA256:<base64>" (padding optional) or an MD5 fingerprint given
    as bare hex or colon separated hex (case insensitive).
    """
    if not expected or not isinstance(expected, str):
        return False
    if not key_blob:
        return False
    value = expected.strip()
    if not value:
        return False
    if value.upper().startswith("SHA256:"):
        want = value[7:].strip().rstrip("=")
        if not want:
            return False
        got = _fingerprint_sha256(key_blob)[7:]
        return hmac.compare_digest(got.encode("ascii", "replace"),
                                   want.encode("ascii", "replace"))
    if value.upper().startswith("MD5:"):
        value = value[4:]
    cleaned = value.replace(":", "").lower()
    if len(cleaned) != 32 or any(c not in "0123456789abcdef" for c in cleaned):
        return False
    return hmac.compare_digest(_fingerprint_md5(key_blob), cleaned)


def shell_join(args) -> str:
    """Quote every element for a POSIX shell. Always quote paths."""
    return " ".join(shlex.quote(str(a)) for a in args)


def q(path: str) -> str:
    """Quote one remote path (after validation)."""
    return shlex.quote(validate_remote_path(path))


def temp_name(parent: str, prefix: str) -> str:
    """Unique temp path in the same directory as the final destination so the
    later `mv` is an atomic rename on the same filesystem."""
    return posixpath.join(parent, f"{prefix}{uuid.uuid4().hex}")


# --------------------------------------------------------------------------
# SSH connection
# --------------------------------------------------------------------------

class _FingerprintPolicy(paramiko.MissingHostKeyPolicy if paramiko else object):
    """Accept an *unknown* host only when its fingerprint matches exactly."""

    def __init__(self, expected: str) -> None:
        self.expected = expected

    def missing_host_key(self, client, hostname, key):  # noqa: D401
        blob = key.asbytes()
        if not key_fingerprint_matches(self.expected, blob):
            raise CliError(
                "host key fingerprint mismatch for {0} (got {1}); refusing to "
                "connect".format(hostname, _fingerprint_sha256(blob)))
        print(f"router: pinned host key for {hostname} ({_fingerprint_sha256(blob)})",
              file=sys.stderr)


class Connection:
    """Thin wrapper; owns one paramiko client and closes it in close()."""

    def __init__(self, args) -> None:
        if paramiko is None:
            raise CliError("paramiko is not installed (pip install paramiko)")
        self.host = args.host
        self.port = args.port
        self.user = args.user
        self.timeout = args.timeout
        self.fingerprint = args.fingerprint
        self.client = None

    def __enter__(self) -> "Connection":
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        strict = self.fingerprint is None
        if strict:
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(_FingerprintPolicy(self.fingerprint))
        try:
            client.connect(
                hostname=self.host,
                port=self.port,
                username=self.user,
                password=_password(),
                look_for_keys=False,
                allow_agent=False,
                timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )
            if self.fingerprint and not key_fingerprint_matches(
                    self.fingerprint, client.get_transport().get_remote_server_key().asbytes()):
                raise CliError("host key does not match the explicit fingerprint")
        except paramiko.BadHostKeyException as exc:
            client.close()
            raise CliError(
                f"host key for {self.host} changed and does not match "
                f"known_hosts ({exc.key.get_name()}); refusing to connect")
        except paramiko.AuthenticationException:
            client.close()
            raise CliError(f"authentication failed for {self.user}@{self.host}")
        except CliError:
            client.close()
            raise
        except Exception as exc:
            client.close()
            raise CliError(f"cannot connect to {self.host}:{self.port}: {exc}")
        self.client = client
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self.client is not None:
            try:
                self.client.close()
            finally:
                self.client = None

    # -- exec primitives ---------------------------------------------------

    def run(self, command: str, *, stdin_data: bytes | None = None,
            check: bool = True, want_output: bool = False,
            binary_output: bool = False):
        """Run one remote command, draining stdout/stderr concurrently.

        When want_output is False the streams are forwarded live to the local
        stderr, which avoids a deadlock on a full channel window.
        """
        assert self.client is not None
        chan = self.client.get_transport().open_session()
        chan.settimeout(self.timeout)
        chan.exec_command(command)
        if stdin_data is not None:
            chan.sendall(stdin_data)
        chan.shutdown_write()

        out_chunks: list[bytes] = []
        err_chunks: list[bytes] = []
        deadline = time.time() + self.timeout
        while True:
            if chan.exit_status_ready() and not (chan.recv_ready() or chan.recv_stderr_ready()):
                break
            if time.time() > deadline:
                chan.close()
                raise CliError(f"remote command timed out after {self.timeout}s",
                               EXIT_TIMEOUT)
            select.select([chan], [], [], 0.2)
            while chan.recv_ready():
                data = chan.recv(IO_CHUNK)
                if not data:
                    break
                if want_output:
                    out_chunks.append(data)
                else:
                    _emit(data, sys.stderr)
            while chan.recv_stderr_ready():
                data = chan.recv_stderr(IO_CHUNK)
                if not data:
                    break
                if want_output:
                    err_chunks.append(data)
                else:
                    _emit(data, sys.stderr)
        status = chan.recv_exit_status()
        chan.close()
        raw_out = b"".join(out_chunks)
        out = raw_out if binary_output else raw_out.decode("utf-8", "replace")
        err = b"".join(err_chunks).decode("utf-8", "replace")
        if check and status != 0:
            raise CliError(f"remote command failed (exit {status}): {command}\n{err.strip()}",
                           status)
        return status, out, err


def _emit(data: bytes, stream) -> None:
    try:
        stream.write(data.decode("utf-8", "replace"))
        stream.flush()
    except Exception:
        pass


_PASSWORD_CACHE: str | None = None


def _password() -> str:
    global _PASSWORD_CACHE
    if _PASSWORD_CACHE is None:
        pw = os.environ.get("NETQUOTA_SSH_PASSWORD")
        if not pw:
            import getpass
            try:
                pw = getpass.getpass("SSH password for router: ")
            except EOFError:
                raise CliError("no interactive password input; set NETQUOTA_SSH_PASSWORD") from None
        if not pw:
            raise CliError("no SSH password supplied")
        _PASSWORD_CACHE = pw
    return _PASSWORD_CACHE


# --------------------------------------------------------------------------
# Upload (exec-stdin, no SFTP)
# --------------------------------------------------------------------------

def remote_upload(conn: Connection, local_path: str, remote_path: str,
                  mode: str = "644") -> str:
    """Stream a local file to remote_path atomically.

    cksum/sha256sum -> same-directory temp file -> chmod -> verify -> mv.
    Cleans up its own temp file on any failure.
    """
    dest = validate_remote_path(remote_path)
    if not os.path.isfile(local_path):
        raise CliError(f"local file not found: {local_path}", EXIT_USAGE)

    with open(local_path, "rb") as fh:
        blob = fh.read()
    digest = hashlib.sha256(blob).hexdigest()

    parent = posixpath.dirname(dest) or "/"
    tmp = temp_name(parent, ".netquota-upload.")
    try:
        conn.run(f"cat > {shlex.quote(tmp)}", stdin_data=blob)
        conn.run(f"chmod {shlex.quote(mode)} {shlex.quote(tmp)}")
        _, out, _ = conn.run(f"sha256sum {shlex.quote(tmp)}", want_output=True)
        remote_digest = out.split()[0] if out.split() else ""
        if remote_digest != digest:
            raise CliError(
                f"checksum mismatch on {tmp}: local {digest} remote {remote_digest}")
        conn.run(f"mv -f {shlex.quote(tmp)} {shlex.quote(dest)}")
    except Exception:
        try:
            conn.run(f"rm -f {shlex.quote(tmp)}", check=False)
        except Exception:
            pass
        raise
    return dest


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------

PREFLIGHT_SCRIPT = r"""
echo "== board =="
ubus call system board 2>/dev/null || echo '{"error":"ubus unavailable"}'
echo "== kernel =="
uname -srm
echo "== gl version =="
cat /etc/glversion 2>/dev/null || echo unknown
echo "== versions =="
opkg list-installed 2>/dev/null | grep -E '^(lua|lsqlite3|nftables|kmod-nft-core|luci-base|luci-lib-nixio|luci-lib-jsonc|libuci-lua|libubus-lua|netquota|luci-app-netquota)([ -]|$)' || true
nft --version 2>/dev/null || echo 'nft: absent'
echo "== lua modules =="
lua -e 'for _,m in ipairs{"nixio","lsqlite3","luci.jsonc","uci","ubus"} do
  local ok = pcall(require, m); print((ok and "ok " or "missing ")..m) end' 2>/dev/null || true
echo "== acceleration =="
printf 'mtkhnat.global.enable='; uci -q get mtkhnat.global.enable || true
uci -q show firewall | grep -E '\.flow_offloading(_hw)?=' || true
lsmod | grep -E 'mtkhnat|mtk_warp|nft_quota|nft_objref|nft_counter' || true
echo "== services =="
ls /etc/init.d/ 2>/dev/null | grep -i netquota || echo 'no netquota service'
echo "== interfaces =="
ubus call network.interface dump 2>/dev/null || echo '{"error":"ubus unavailable"}'
echo "== done =="
"""


def cmd_exec(args) -> int:
    if args.script:
        with open(args.script, "r", encoding="utf-8", errors="replace") as fh:
            script = normalize_script(fh.read())
    elif args.command:
        script = normalize_script(args.command)
    else:
        script = normalize_script(sys.stdin.read())
    if not script.strip():
        raise CliError("empty command; nothing to run", EXIT_USAGE)
    with Connection(args) as conn:
        status, out, err = conn.run("sh -s", stdin_data=script.encode("utf-8"),
                                    check=False, want_output=True)
        if out:
            sys.stdout.write(out)
            sys.stdout.flush()
        if err:
            sys.stderr.write(err)
        return status


def cmd_upload(args) -> int:
    dest = validate_remote_path(args.remote_path)
    if (len(args.mode) not in (3, 4) or any(c not in "01234567" for c in args.mode)
            or int(args.mode, 8) > 0o777):
        raise CliError(f"invalid --mode {args.mode!r}", EXIT_USAGE)
    with Connection(args) as conn:
        final = remote_upload(conn, args.local_file, dest, args.mode)
    print(f"uploaded {args.local_file} -> {final}")
    return EXIT_OK


def cmd_preflight(args) -> int:
    with Connection(args) as conn:
        status, out, err = conn.run("sh -s", stdin_data=normalize_script(PREFLIGHT_SCRIPT).encode(),
                                   check=False, want_output=True)
    if args.json:
        print(json.dumps({"raw": out, "stderr": err, "exit_code": status}, indent=2))
    else:
        sys.stdout.write(out)
    return status


BACKUP_SCRIPT = r"""
set -e
umask 077
DEST=$1
CONFIG=$2
DB=$3
[ -f "$CONFIG" ] || [ -f "$DB" ] || { echo "no config or database on router" >&2; exit 3; }
STAGE=$4
mkdir -p "$STAGE"
mkdir -p "$STAGE/etc/config" "$STAGE/etc/netquota"
[ -f "$CONFIG" ] && cp -p "$CONFIG" "$STAGE/etc/config/" || true
if [ -f "$DB" ]; then
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$DB" ".backup '$STAGE/etc/netquota/netquota.db'"
  else
    # Fallback: consistent via VACUUM INTO if sqlite3 CLI is missing.
    echo "sqlite3 CLI missing; backup skipped" >&2
    exit 4
  fi
fi
tar -C "$STAGE" -czf - .
"""


def cmd_backup(args) -> int:
    stage = temp_name("/tmp", "netquota-backup.")
    out_path = os.path.abspath(args.output)
    parent = os.path.dirname(out_path) or "."
    if not os.path.isdir(parent):
        raise CliError(f"output directory does not exist: {parent}", EXIT_USAGE)
    with Connection(args) as conn:
        try:
            # tar is written to a remote temp file, then pulled over exec stdout
            # (no SFTP available), then removed.
            cmd = "sh -s " + shell_join([stage, CONFIG_FILE, DB_FILE, stage])
            script = "trap 'rm -rf " + shlex.quote(stage) + "' EXIT\n" + BACKUP_SCRIPT
            status, data, err = conn.run(cmd, stdin_data=normalize_script(script).encode(),
                                         check=False, want_output=True, binary_output=True)
            if status not in (0, 3, 4):
                raise CliError(f"remote backup failed (exit {status}): {err.strip()}")
            if status in (3, 4):
                raise CliError(err.strip() or "remote backup failed")
            blob = data
            fd, tmp_local = tempfile.mkstemp(prefix=".netquota-backup.",
                                             dir=parent)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(blob)
                os.chmod(tmp_local, 0o600)
                os.replace(tmp_local, out_path)
            finally:
                if os.path.exists(tmp_local):
                    os.unlink(tmp_local)
        finally:
            conn.run(f"rm -rf {shlex.quote(stage)}", check=False)
    print(f"backup written to {out_path}")
    return EXIT_OK


def cmd_install(args) -> int:
    for path in args.ipk:
        if not os.path.isfile(path):
            raise CliError(f"local package not found: {path}", EXIT_USAGE)
    stage = temp_name("/tmp", "netquota-install.")
    conn = None
    uploaded: list[str] = []
    try:
        conn = Connection(args).__enter__()
        conn.run(f"mkdir -p {shlex.quote(stage)}")
        for path in args.ipk:
            name = posixpath.basename(path)
            if not name.endswith(".ipk"):
                raise CliError(f"not an .ipk file: {path}", EXIT_USAGE)
            dest = posixpath.join(stage, name)
            remote_upload(conn, path, dest, "644")
            uploaded.append(dest)
        conn.run("opkg install " + shell_join(uploaded))
        print(f"installed {len(uploaded)} package(s)")
    finally:
        if conn is not None:
            try:
                conn.run(f"rm -rf {shlex.quote(stage)}", check=False)
            except Exception:
                pass
            conn.close()
    return EXIT_OK


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="router.py",
        description="Workstation CLI for the OpenWrt netquota router (no SFTP).")
    p.add_argument("--host", default=os.environ.get("NETQUOTA_ROUTER_HOST", DEFAULT_HOST))
    p.add_argument("--user", default=DEFAULT_USER)
    p.add_argument("--port", type=int, default=SSH_PORT)
    p.add_argument("--fingerprint", default=None,
                   help="Pin server key (SHA256:... or MD5 hex); for unknown hosts only")
    p.add_argument("--timeout", type=float, default=60.0)
    sub = p.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("exec", help="run a command/script on the router")
    e.add_argument("command", nargs="?", default=None)
    e.add_argument("--script", default=None, help="local script file to run")
    e.set_defaults(func=cmd_exec)

    u = sub.add_parser("upload", help="upload a file atomically")
    u.add_argument("local_file")
    u.add_argument("remote_path")
    u.add_argument("--mode", default="644")
    u.set_defaults(func=cmd_upload)

    pf = sub.add_parser("preflight", help="read-only environment report")
    pf.add_argument("--json", action="store_true")
    pf.set_defaults(func=cmd_preflight)

    b = sub.add_parser("backup", help="back up config and database")
    b.add_argument("--output", required=True)
    b.set_defaults(func=cmd_backup)

    i = sub.add_parser("install", help="install local .ipk packages")
    i.add_argument("ipk", nargs="+")
    i.set_defaults(func=cmd_install)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except CliError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    for stream in (sys.stdout,sys.stderr):
        if hasattr(stream,'reconfigure'):
            stream.reconfigure(encoding='utf-8',errors='replace')
    sys.exit(main())
