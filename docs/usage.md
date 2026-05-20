# Usage — every verb, with examples

This is the cookbook: scenario-driven examples of every `zz`
verb. For the grammar reference (parser rules, modifier set
semantics, exit codes) see [`../COMMANDS.md`](../COMMANDS.md)
and [`commands.md`](commands.md). For the scriptable contract
(`--json` / `--quiet` event schema) see
[`scriptable.md`](scriptable.md).

Every example assumes you've finished setup (`zz c`) and have
unlocked at least once with `zz z`. The agent stays up between
commands, so day-to-day `zz file.md` works without re-typing
the passphrase.

---

## Conventions in this page

- **Default verb is upload.** `zz file.md` ≡ `zz s file.md`.
- **`<alias>`** below is whatever you named your profile in
  `zz c`, e.g. `work-nc`, `home-gdrive`.
- **`<target>`** is the provider host + remote root, e.g.
  `nextcloud.example.org/zz-drop` or `gdrive/uploads`.
- **Trailing-`/`** on the last argument of `s` / `d` switches it
  from "source" to "destination directory". This is the only
  positional magic in the grammar.

---

## Upload — `s` family

### Single file

```sh
zz notes.md                       # default verb: upload to <remote_root>/notes.md
zz s notes.md                     # explicit form (identical)
zz s ~/Desktop/report.pdf         # absolute path → uploads as report.pdf
```

After:

```
uploaded notes.md 1.2 KiB → work-nc · nextcloud.example.org/zz-drop
```

### Several files at once

```sh
zz a.md b.md c.md                 # three uploads, each at <remote_root>/<basename>
```

### Put files into a remote sub-directory

The trailing `/` on the *last* argument names the remote
destination directory. The other arguments are sources.

```sh
zz a.md b.md docs/                # both end up at <remote_root>/docs/{a.md,b.md}
zz s receipt.pdf 2026/may/        # → <remote_root>/2026/may/receipt.pdf
```

A trailing `/` argument *alone* is rejected (no source files):

```sh
zz s docs/                        # error: `s` requires at least one source
```

### Compress on the fly — `sx`

zstd compresses the file before upload. The cloud sees
`<name>.zst`. Files below ~4 KiB skip compression (zstd's frame
header would inflate them).

```sh
zz sx big-log.txt                 # → <remote_root>/big-log.txt.zst
zz sx report.pdf 2026/may/        # trailing-`/` rule still applies
```

The `uploaded` event reports `compressed_pct` (`0..=99`,
read as "saved N%") so you can verify the ratio after the fact:

```sh
zz sx data.json --json
# {"v":"1","event":"uploaded","ts":"...","file":"data.json.zst",
#  "bytes":312,"compressed_pct":87,"alias":"work-nc",
#  "target":"nextcloud.example.org/zz-drop"}
```

### Whole-directory upload — `sa` / `sar`

Upload every regular file inside a directory. `sa` is one level,
`sar` recurses. Dotfiles (`.git/`, `.bashrc`) and symlinks are
skipped.

```sh
zz sa .                           # upload all top-level files in cwd
zz sa /tmp/proj                   # absolute source dir
zz sa . backup/                   # land everything under <remote_root>/backup/
zz sar ./project backup/snap/     # recursive, keeps relative paths
```

A successful `sa` ends with a `batch_summary`:

```sh
zz sa . --json | tail -1
# {"v":"1","event":"batch_summary","ts":"...","total":12,"ok":12,"failed":0,"exit_code":0}
```

### Whole-directory as a bundle — `sax` / `sarx`

Tar + zstd the directory into a single `<dirname>.tar.zst` blob.
Useful for snapshotting a small/medium project tree as one
artifact you can `dx` later to recreate the tree on a fresh
machine.

```sh
zz sax .                          # upload current dir as <cwd-name>.tar.zst
zz sax ./project                  # → <remote_root>/project.tar.zst
zz sarx ./project backup/snap/    # recursive bundle, placed under backup/snap/
```

The cap on bundle size is whatever your provider accepts as a
single PUT; for very large trees, switch to per-file `sa`/`sar`
so the operation is resumable per file.

---

## Download — `d` family

### Single file

```sh
zz d notes.md                     # → notes.md in cwd
zz d notes.md ~/Documents/        # trailing-`/` → place under ~/Documents/
```

### Several files into a directory

```sh
zz d a.md b.md c.md ~/inbox/      # → ~/inbox/{a.md,b.md,c.md}
```

### Glob matching against the remote

zsh / bash can't expand globs against a cloud directory — that
requires a `LIST` round-trip. zz-drop expands glob patterns
*server-side* against the parent prefix:

```sh
zz d 'reports/*.pdf'              # quote it; don't let the local shell try first
zz d 'Q*.pdf'                     # matches Quectel.pdf, Quartely-2024.pdf, …
zz d 'h?llo.txt'                  # ? matches exactly one character
```

If you forget the quotes, your shell expands `*` against the
*local* cwd before `zz` sees it — that's almost never what you
want for a download.

### Decompress on download — `dx`

`dx` looks at the bytes after download. If they start with the
zstd magic, it writes a decompressed sibling. If the
decompressed payload is a tar archive (the format produced by
`sax`/`sarx`), it extracts into a sibling directory.

```sh
zz dx big-log.txt.zst             # → big-log.txt.zst + big-log.txt (decompressed)
zz dx project.tar.zst             # → project.tar.zst + project/ (extracted)
```

Extraction refuses to overwrite an existing target directory.
Delete or rename it first.

### Whole-tree download — `da` / `dar`

Mirror the remote root (or a sub-prefix) onto local disk.
`da` is one level, `dar` recurses.

```sh
zz da                             # everything at <remote_root>/ → cwd
zz da ~/snapshot                  # → ~/snapshot/<files>
zz da ~/snapshot docs/            # only <remote_root>/docs/<top-level> → ~/snapshot/
zz dar ~/full project/build/      # mirror <remote_root>/project/build/ → ~/full/
```

`dax` / `darx` (bulk per-file decompress) is reserved for a
later release. Use `dx <bundle>.tar.zst` per bundle for the
symmetric form.

---

## Unlock / lock / wipe — `z` / `q` / `w`

### Unlock — `z`

Reads the encrypted container, prompts (or reads) the
passphrase, and hands the decrypted profile to the local agent.
After this, daily commands don't ask again until the agent's
TTL expires or `q` is called.

```sh
zz z                              # unlocks profiles-local.zz, picker if multi-alias
```

When the container holds more than one alias, the picker
prompts on stdin. To bypass the picker in the daily flow, set
a default once:

```sh
zz z                              # picks an alias, caches the choice
# every subsequent `zz z` honours the cached default
```

In a script:

```sh
zz z --passphrase-file ~/.zz.pass --alias work-nc --json
# {"v":"1","event":"unlocked","ts":"...","alias":"work-nc",
#  "target":"nextcloud.example.org/zz-drop"}
```

### Lock — `q`

```sh
zz q                              # zeroize the in-RAM profile, stop the agent
```

Idempotent — running it twice in a row succeeds twice.

### Wipe — `w`

Destructive. Removes the encrypted container, `config.toml`,
sidecars, agent runtime dir. Requires typing `wipe` to confirm
in interactive mode.

```sh
zz w                              # interactive: prompts for the word "wipe"
zz --yes w                        # auto-confirm (required in --json / --quiet)
```

The same env-based escape hatch is honoured for legacy CI:
`ZZ_DROP_CONFIRM_WIPE=yes zz w`.

---

## TUI — `c`

Open the configuration / setup wizard. Use this to add or edit a
profile, change a provider, walk the Nextcloud Login Flow,
etc.

```sh
zz c                              # launches the zz-tui binary
```

`zz c` is interactive-only. In `--json` / `--quiet` it exits
`2` with `failed reason=interactive_only`.

---

## Doctor — `f`

Read-only health check: paths the binary uses, container files
on disk, agent socket / token status, SACS classifier state,
build identity.

```sh
zz f                              # verbose human output
zz f --json                       # one doctor_check per probe, then doctor_summary
zz f --quiet                      # one line per probe: "<name> ok/fail"
```

Useful for "is my install / agent / profile in a sane state?"
without touching the cloud.

---

## Scriptable mode — patterns

The contract and the full event schema live in
[`scriptable.md`](scriptable.md). Three idiomatic shapes:

### Pin against a clean shell

```sh
export ZZ_OUTPUT=json
export ZZ_CONFIG_DIR=/run/secrets/zz-drop     # isolate state tree
export ZZ_PASSPHRASE_FILE=/run/secrets/zz.pass
export ZZ_ALIAS=ci-bot

zz z | jq -e '.event=="unlocked"' >/dev/null
trap 'zz q' EXIT
zz s artifact.zip
```

### Branch on result

```sh
zz s artifact.zip --json \
  | tee >(jq -c 'select(.event=="failed")' >&2) \
  | jq -e 'select(.event=="batch_summary").exit_code==0' >/dev/null
```

### Use the exit code only

```sh
if zz d 'reports/*.pdf' --quiet >/dev/null; then
  echo "downloaded ok"
else
  echo "downloaded failed with code $?"
fi
```

### Resolve a glob and post-process

```sh
zz d 'logs/*.gz' --json --alias web-prod \
  | jq -r 'select(.event=="downloaded") | .file' \
  | xargs -I{} zstd -d {}
```

---

## Doctor checks at a glance

| Probe | Meaning |
|---|---|
| `container_local` | `profiles-local.zz` present? |
| `container_remote` | `profiles-remote.zz` present? |
| `agent_socket` | Unix socket present? |
| `agent_unlocked` | agent reachable AND profile unlocked? |
| `sacs_state` | SACS classifier — `S0` (fresh) … `S4` (ready, two containers) |
| `build_id` | current binary build identity |

A failing `agent_unlocked` is the most common "why isn't this
working" cause when a daily command says `agent_locked`.

---

## Troubleshooting cheat sheet

| Symptom | Likely cause | Fix |
|---|---|---|
| `failed reason=agent_locked` (exit 10) | scriptable mode, no `zz z` yet | `zz z --passphrase-file <path>` first |
| `failed reason=passphrase_file_permissions` (exit 11) | passphrase file mode > 0600 or owner ≠ current uid | `chmod 0600 <path>`; ensure ownership |
| `failed reason=alias_ambiguous` (exit 2) | multiple aliases, no `--alias`/`ZZ_ALIAS`/cache | `--alias <name>` or `zz z` once interactively |
| `failed reason=interactive_required` on `zz w` | scriptable wipe without confirmation | pass `--yes` |
| `failed reason=container_ambiguous` | both `profiles-local.zz` and `profiles-remote.zz` exist | `--local` or `--remote` |
| `no remote matches` on `zz d 'pattern'` | shell expanded the glob locally | quote the pattern |
| `is not zstd-compressed` from `zz dx` | the file isn't a `.zst` — `dx` is no-op | rename or drop the `x` |
| `invalid peer certificate` on any provider call | corporate TLS-inspection proxy or self-hosted provider with private CA | install the corp CA in the system trust store (the OS-level keychain / certificate store), or export `SSL_CERT_FILE=/path/to/corp-ca.pem` and re-run |

For anything else, run `zz f --json` and read the `doctor_check`
records — most state-related failures show up there.

## Behind a corporate TLS-inspection proxy

zz-drop's HTTPS clients use the **operating system trust store**.
If your administrator has installed the corporate root CA in the
system keychain (macOS) / certificate store (Windows) /
`/etc/ssl/certs` (Linux), it works out of the box: zz-drop trusts
the same set of issuers that your browser, `curl`, `ssh`, and
package managers trust.

If you only have the CA as a `.pem` file and no permission to
install it system-wide, point zz-drop at the file directly:

```sh
export SSL_CERT_FILE=/path/to/corp-ca.pem
zz file.md
```

While `SSL_CERT_FILE` is set, **only** the certificates in that
PEM are trusted. Unset it to go back to the system trust store.
