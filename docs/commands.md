# zz-drop CLI commands

Canonical command table for the `zz` binary. The user-facing
manual with worked examples and output samples lives in
[`zz-drop/COMMANDS.md`](../COMMANDS.md); this page is
the spec.

## Quick reference

```text
zz <file>...                       upload (default verb)
zz s <file>... [<remote-dir>/]     upload, optional remote subdir
zz sx <file> [<remote-dir>/]       upload, compressed
zz sa <dir> [<remote-prefix>]      upload top-level files
zz sar <dir> [<remote-prefix>]     upload recursively
zz sax <dir> [<remote-prefix>]     upload as one .tar.zst bundle
zz sarx <dir> [<remote-prefix>]    upload recursively as one .tar.zst

zz d <file>... [<local-dir>/]      download (raw bytes)
zz dx <file>.zst [<local-dir>/]    download + decompress (or extract bundle)
zz da [<local-dest> [<remote/>]]   download all top-level files
zz dar [<local-dest> [<remote/>]]  download all files recursively

zz z                unlock the local container into the agent
zz q                lock the agent
zz w                wipe local zz-drop state (with confirmation)
zz c                launch the configuration TUI (zz-tui)
zz f                doctor / diagnostics
```

## Reserved verbs

| Verb | Args | Meaning |
|---|---|---|
| (none) | 1+ paths | Upload (default — first non-reserved token wins) |
| `s` | 1+ paths | Upload (explicit alias of the default) |
| `d` | 1+ remote names | Download |
| `z` | — | Unlock the local container into the agent |
| `q` | — | Lock (zeroize the in-RAM container) |
| `w` | — | Wipe local zz-drop state (with typed `y` confirmation) |
| `c` | — | Launch the configuration TUI (`zz-tui` on `$PATH`) |
| `f` | — | Doctor / diagnostics |

## Bulk variants — `s` / `d` with the `a` modifier

`a` switches to bulk mode: a single positional `<dir>` argument
is required (the operator types `.` for cwd).

| Verb | Args | Meaning |
|---|---|---|
| `sa` | `<dir>` | Upload top-level regular files of `<dir>` (non-recursive) |
| `sar` | `<dir>` | Upload all files under `<dir>` (recursive, preserves relative path) |
| `da` | `<dest>` | Download all top-level remote files into `<dest>` |
| `dar` | `<dest>` | Download the remote tree into `<dest>` (recursive) |

## Modifiers

The composite verbs `s` and `d` accept a *set* of single-letter
modifiers in any order. Set semantics: `sar` ≡ `sra`, `sarx` ≡
`sxar` ≡ `sxra`, etc.

| Letter | On `s` | On `d` | v1 status |
|---|---|---|---|
| `a` | bulk: needs `<dir>` | bulk: needs `<dest>` | implemented |
| `r` | recurse (with `a` only) | recurse (with `a` only) | implemented |
| `x` | zstd-compress; bundle as `.tar.zst` when paired with `a` | decompress (and extract `.tar.zst` into a sibling dir) | implemented for single-file (`sx` / `dx`) and bundle upload (`sax` / `sarx`); bulk decompress (`dax` / `darx`) returns `EXIT_NOT_IMPLEMENTED` |
| `e` | reserved (future encryption modifier) | (no `e` on `d` — download is always magic-detected) | rejected with explicit "not implemented in v1" message |

`r` without `a` is rejected (`zz sr` / `zz drx` → `unknown
modifier r`). Duplicate letters are rejected (`zz saa` →
`modifier a repeated`).

## Pipeline (deterministic, regardless of letter order)

**Upload (`s` family):**

```
file(s)  →  [tar bundle if (a or ar) and x]
         →  [zstd if x]
         →  upload as <name>(.zst|.tar.zst)
```

**Download (`d` family):**

```
remote bytes
  → [zstd-decompress if x and bytes start with zstd magic]
  → [extract into sibling dir if decompressed bytes have tar ustar magic at offset 257]
  → write
```

Decompression is **size-capped** (`MAX_DECOMPRESSED_BYTES`, 512 MiB):
remote bytes are attacker-influenced, and zstd's expansion ratio is
unbounded, so `dx` refuses output beyond the cap rather than risk a
decompression-bomb OOM. The tar extraction that may follow is bounded by
that already-capped buffer (and the `tar` crate rejects `..`/absolute
members).

If the `e` modifier ever lands, compression will run before
encryption — encrypted bytes are high-entropy and won't compress
further.

## Parser rule

If the first argument exactly matches a reserved verb (or one
of the composite forms `s[a r x]+` / `d[a r x]+`), it is the
command. Otherwise the entire argv is treated as upload paths.

To upload a file whose name happens to match a verb:

```bash
zz ./z
zz ./w
```

## Exit codes

Stable from 1.0.0 onward. New codes may be added; renumberings
are breaking. Each code maps 1:1 to a `reason` string on the
NDJSON `failed` event — see [`scriptable.md`](scriptable.md).

| Code | Meaning |
|---|---|
| `0` | Success |
| `2` | Usage error (flag/arg parse, `interactive_required`, `interactive_only`, `alias_ambiguous`, `container_ambiguous`) |
| `3` | Recognized but not implemented yet |
| `5` | Agent unreachable (socket present but not accepting / RPC failed) |
| `6` | Profile not found |
| `7` | Decryption failed |
| `8` | Wipe cancelled |
| `9` | Provider error (Nextcloud / Google Drive / OneDrive / Dropbox) |
| `10` | Agent reachable but profile locked (scriptable mode — never auto-unlocks) |
| `11` | Passphrase file mode > 0600 or owner mismatch |
| `127` | `zz c` could not find `zz-tui` on `$PATH` |

## Global flags

Accepted before the verb on any invocation. After the first
non-flag positional, parsing stops. Use `--` to terminate flag
parsing explicitly.

| Flag | Value | Notes |
|---|---|---|
| `--json` | — | NDJSON on stdout. Mutually exclusive with `--quiet`. |
| `--quiet` | — | One minimal text line per result. |
| `--passphrase-file <p>` | path | Read passphrase from file. Strict mode/owner check (see `SECURITY.md`). |
| `--alias <name>` | string | Skip the picker, pre-select this alias. |
| `--local` | — | Force `profiles-local.zz`. |
| `--remote` | — | Force `profiles-remote.zz`. |
| `--yes` | — | Auto-confirm `zz w` in scriptable mode. |

`--name=value` is accepted everywhere `--name value` is.

## Environment variables

Applied when no command-line flag overrides them. Precedence:
flag > env > default.

| Var | Type | Default | Override flag |
|---|---|---|---|
| `ZZ_OUTPUT` | `text`\|`json` | `text` | `--json` |
| `ZZ_PASSPHRASE_FILE` | path | unset | `--passphrase-file` |
| `ZZ_ALIAS` | string | unset | `--alias` |
| `ZZ_CONTAINER` | `local`\|`remote` | unset | `--local`/`--remote` |
| `ZZ_CONFIG_DIR` | absolute path | OS default | env-only — redirects the entire state tree to `<root>/{config,cache,runtime}` |

`ZZ_OUTPUT=quiet` is **not** accepted as an env value (quiet
mode is flag-only). `ZZ_PASSPHRASE=<value>` is **explicitly not
supported** — env values leak via `/proc`, `ps eww`, container
debug.

For the full scriptable contract (NDJSON event schema, reason
table, CI cookbook) see [`scriptable.md`](scriptable.md). The
machine-checkable JSON Schema is at
[`scriptable/zz-drop-output.v1.json`](scriptable/zz-drop-output.v1.json).
