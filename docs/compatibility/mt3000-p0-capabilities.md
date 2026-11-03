# MT3000 — P0 Capability Tests (Observed)

Executed: live router probes via loopback bridge `http://127.0.0.1:51379/run`.
All results below are **observed output**, not placeholders. Read-only except
one create/delete of my own unhooked nft table (cleaned, `CONFIRMED_GONE`).

> Supersedes the earlier BLOCKED revision (that attempt failed on a missing
> `NETQUOTA_SSH_PASSWORD` env var before any router contact; no state was changed).

## Device / version baseline

| Fact | Observed |
|---|---|
| uname | `Linux GL-MT3000 5.4.211 aarch64` |
| `/etc/glversion` | `4.11.0` |
| OpenWrt | `21.02-SNAPSHOT r15812+926-46b6ee7ffc` (taints: `busybox override`) |
| Target | `mediatek/mt7981`, arch `aarch64_cortex-a53` |
| Model | `GL.iNet GL-MT3000`, board `glinet,mt3000-snand` |
| nft | `v0.9.6 (Capital Idea #2)` — **`-j` unsupported**: exit 1, `JSON support not compiled-in` |
| fw | `fw3` (no `/sbin/fw4`), iptables `xt_FULLCONENAT` path in `fullconenat` |
| Lua | `5.1.5` (PUC-Rio) |
| OpenSSL | `1.1.1q` |
| lsqlite3 | `0.9.5-1`, SQLite engine `3.33.0` |
| Modules | `nft_quota`, `nft_objref`, `nft_counter` loaded (.ko present for 5.4.211) |

### nft and legacy firewall namespaces

`nft list tables` was empty before the probe and listed the probe table while
it existed. This is expected: fw3 uses legacy iptables on this firmware, whose
tables are not nftables tables. Enumeration is working. Empty nft output does
not mean that the legacy firewall is absent or that a production hook is safe.

## 1. Acceleration (MTK HNAT) — knob identified, nothing changed

Acceleration is **on** today: `uci get mtkhnat.global.enable` → `1`.
Enabled at boot via `S19mtkhnat`, `S20mtk-hwnat-post`, `S99shortcut-fe`.

Exact runtime knob (two layers):

1. **Kernel hook toggle** — `/sys/kernel/debug/hnat/hook_toggle` (exists). Written by
   `/etc/init.d/mtk-hwnat-post` (full script is ~14 lines):
   ```sh
   local enable=$(uci -q get mtkhnat.global.enable)
   [ "$enable" != "1" ] && enable=0
   echo $enable > /sys/kernel/debug/hnat/hook_toggle
   ```
   Guarded by `[ -d /etc/wireless/mediatek ]` (present).
2. **`/etc/init.d/shortcut-fe`** reads the same uci key (line 43) and force-writes
   `0` to `hook_toggle` (line 45) under its own conditions.

`/etc/init.d/mtkhnat` itself only runs procd `/sbin/mtkhnat` (`START=19`,
`procd_add_reload_trigger "mtkhnat"`), independent of the hook byte.

Deferred disable path (for later, **not executed**): `uci set mtkhnat.global.enable=0`
then re-run `mtk-hwnat-post`, or write `0` to `hook_toggle`. A future test must
verify disable at the **hook** layer, not merely stop the daemon.
`hnat_enable` as a name: **no references found** (grep across `/etc`).
Full 129-queue `mtkhnat` config not reproduced here (only `global.enable=1`,
`hqos=0`, `actype=1` relevant).

## 2. nft shared quota + dual counters — **PASS (syntax corrected)**

**First script containing a hook was rejected atomically; no hook was ever
committed.** The assumed block syntax
`add quota inet T q_acct { over 4096 bytes }` is invalid in 0.9.6
(`unexpected '{', expecting number`). nft applies a file as one atomic
transaction, so the whole batch failed and the table never existed — confirmed
independently by the `absent` pre-check and the failing `list`/`delete`.

Correct grammar (0.9.6):
```
add quota inet netquota_p0_probe q_acct over 4096 bytes
```

Applied as one transaction, gated by `nft -c` (`CHECK_OK`, exit 0), `apply_exit=0`:

```
table inet netquota_p0_probe {
	quota q_acct { over 4 kbytes }
	counter c_up   { packets 0 bytes 0 }
	counter c_down { packets 0 bytes 0 }
	chain pr {
		ip saddr 198.18.200.2 counter name "c_up"   quota name "q_acct"
		ip saddr 198.18.200.3 counter name "c_up"   quota name "q_acct"
		ip daddr 198.18.200.2 counter name "c_down" quota name "q_acct"
		ip daddr 198.18.200.3 counter name "c_down" quota name "q_acct"
	}
}
```

- One `quota q_acct` object (handle 1), two counters (handles 2,3), four rules
  (handles 5–8) referencing them → **shared named quota + named directional
  counters proven**. Counters read back `packets 0 bytes 0` (no traffic).
- Chain `pr` has **no hook line** → unhooked ordinary chain, no traffic path.
- Cleanup via `trap ... EXIT INT TERM` → **`CONFIRMED_GONE`**.

### Reporting caveat (do not misread)

Grep assertions for `quota name q_acct` / `counter name c_up` returned **0**
because `nft list` prints refs **quoted** (`quota name "q_acct"`). The four
references are visibly present above. The 0 counts are a **grep-quoting
artifact, not a quota failure**.

### Not yet verified (real forwarding precision)

Kernel object creation/reference semantics only. Still open: quota accounting
under real forwarded traffic; exhaustion behaviour — these probe rules had
no drop verdict, so limit enforcement is **untested**. A production rule must
explicitly combine the quota match with the intended verdict;
counter accuracy per direction under conntrack/HNAT offload; hook-priority
interaction with `fw3`; MT6000 parity.

## 3. Lua interface probes

`nixio` loads as a single table; submodules are **not** separate Lua modules
(`require "nixio.crypto"` → `module not found`; `nixio` has 67 top-level keys).

- `nixio.crypto` → **nil (ABSENT)**. `nixio.crypt` is a **function**, not a cipher
  table: `nixio.crypt("synthetic-pass","ab")` → 13-char crypt(3)-style hash.
- `nixio.bin` → `b64decode b64encode crc32 hexlify unhexlify`.
  `hexlify("\1\2\255")` → `0102ff`.
- `nixio.getrandom` → **nil (ABSENT)**.
- `nixio.open("/dev/urandom","r")` → **OK**, 16 bytes read.
- **No `digest`/`hash`/`hmac`/`pbkdf2`** in any `nixio.*` member.

Consequence: PBKDF2 **cannot** be composed from nixio crypto here. Verified
available primitives (synthetic values only, no real secrets):
- HMAC-SHA256: `openssl dgst -sha256 -hmac 'synthetic-key'` on `synthetic-msg`
  → `29e34a3ae99c4304888cc2f8216d9b20aaefad3921f36de535686edec22225a6`.
- PBKDF2 via `openssl enc -pbkdf2 -iter 1000 -pass … -S 0011223344556677`
  → derived `key=93E6CAE7389C1FA6C1EBD5F8D31DFF1CDE325660BF4CE841A4DF8B26D5B7348F`
  (deterministic, exit 0). Note `openssl kdf` subcommand is **absent** in 1.1.1q
  (`Invalid command 'kdf'`), so `enc -pbkdf2 -P` (print key) is the usable form.

Additional direct verification by the coordinating agent: the native
`nixio.crypt("synthetic-password", "$6$rounds=10000$syntheticsalt$")` call
successfully returned a 116-character SHA512-crypt result beginning with
`$6$rounds=10000$`. SHA512-crypt with a configurable cost, CSPRNG salt and
constant-time comparison is therefore an available in-process implementation
route. The synthetic cost used in this capability test is not a production
cost recommendation. Ordinary salted SHA-256 is not a suitable fallback.

### SQLite (in-memory only, no disk file)

`open_memory()` OK; engine `3.33.0`; constants `OK=0 DONE=101 ROW=100`.
`prepare` → `bind_values` → `step` → `reset` → re-`bind_values` → `finalize`
all true; two inserts → `count=2`. `BEGIN IMMEDIATE`/`COMMIT` OK. Rollback
proof: count inside tx `3` → after `ROLLBACK` `2`. Rows
`acct-a=4097, acct-b=8192`. `close` OK. **`in_transaction()` ABSENT** — do not
code against it. `db:prepare` on a missing table does **not** raise; check the
return value (API is not exception-throwing).

## 4. Packages

- `/var/opkg-lists/` → **empty** (no cached index). Feeds: GL.iNet
  `fw.gl-inet.cn` v21.02.3, three `src/gz` lines (core / gli_pub / gli_packages).
- `opennds` / `nodogsplash`: **not installed**, no cache → no local version.
- Index-only download (local Windows, no install) of
  `…/packages/Packages.gz` (783,465 B → 3,831,323 B, 8,467 packages):
  **`opennds 9.8.0-2`**, **`nodogsplash 5.0.0-1`** available upstream.
- Binaries present: `dnsmasq nft iptables ip6tables tc iwinfo ubus uci lua
  sqlite3 openssl dropbear odhcpd`. **`hostapd` ABSENT** (vendor wifi stack).
- Existing captive/portal stack: `gl-sdk4-portal`, `kmod-wifidog-ng`,
  `gl-sdk4-wifi`, `lsqlite3` + `lsqlite3-lua5.4`, `liblua5.1.5`, `liblua5.4`.

## Limitations / residual gaps

- All nft work **unhooked**: zero packet-forwarding evidence.
- Acceleration left **enabled**; disable path identified but unexecuted.
- Native SHA512-crypt verified; production cost and login latency still need testing.
- MT6000 (different SoC/wifi) parity unverified; MT3000-only data.

## Next decisions

1. Validate native SHA512-crypt production cost and password verification.
2. Test the shared quota match with explicit drop verdict and real traffic.
3. Plan the first **hooked** test in an isolated priority band with a rollback
   timer, after agreeing the HNAT/offload interaction question.
4. Verify the software forwarding path with acceleration disabled before
   enabling managed access; unverified offload bypass must prevent activation.
