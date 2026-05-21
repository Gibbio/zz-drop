# SACS — state-aware contextual suggestions

`zz` ships its own shell completion engine. The shell script is dumb
(`zz --completions <shell>` produces ~30-40 lines per shell) and
relays to a hidden subcommand, `zz __complete <args>`, that owns all
the ranking and filesystem / agent observation. The brain is the
binary: rebuilding `zz` is the only thing needed to update the
suggestions, the script never changes.

## Installation

Both supported install paths wire completions automatically.
For everyone else — `cargo install --git`, build-from-source,
or to fix a setup that didn't quite take — the single command
`zz --setup-completions` does the same thing.

### The one-shot command

```sh
zz --setup-completions              # auto-detect $SHELL
zz --setup-completions zsh          # force a specific shell
zz --check-completions              # read-only status report
zz --setup-completions --uninstall  # remove cleanly
```

What `--setup-completions` does, end-to-end:

1. Detect the shell (`$SHELL`, or the explicit positional).
2. Write the completion script file to the canonical XDG path
   (table below). Idempotent — re-running with the same content
   is a no-op; changed content is overwritten.
3. For zsh / bash, append (or update) a single delimited block in
   `~/.zshrc` / `~/.bashrc`:

   ```
   # >>> zz-drop SACS >>>
   # Added by `zz --setup-completions` — to remove, delete this block.
   fpath=("$HOME/.zfunc" $fpath)
   autoload -U compinit && compinit -i
   # <<< zz-drop SACS <<<
   ```

   Framework-aware: if `oh-my-zsh`, `prezto`, `zinit`, `antibody`,
   `antidote`, `znap`, `zimfw` or `zplug` is referenced in the rc
   file, the block contains only the `fpath` line — the framework
   owns `compinit`.

4. For fish, no rc edit is needed — fish auto-loads everything
   under `~/.config/fish/completions/`.

The two marker lines (`# >>> zz-drop SACS >>>` /
`# <<< zz-drop SACS <<<`) are stable across versions, so a future
`zz --setup-completions --uninstall` can find and remove the block
even if it was written by an older binary.

### Where files land

| Shell | Primary path | Alias file |
|---|---|---|
| bash | `${XDG_DATA_HOME:-~/.local/share}/bash-completion/completions/zz-drop` | `…/completions/zz` |
| zsh  | `${ZDOTDIR:-~}/.zfunc/_zz` | — |
| fish | `${XDG_CONFIG_HOME:-~/.config}/fish/completions/zz.fish` | `…/completions/zz-drop.fish` |

Bash and fish lazy-load their completion files **by command name**
(`bash-completion/completions/<cmd>`,
`fish/completions/<cmd>.fish`). A single file named `zz-drop`
would never be found when the operator types `zz <TAB>` from a
fresh shell, and vice versa. So `--setup-completions` drops the
alias file next to the primary — a relative symlink where the
platform supports it (`zz → zz-drop`, `zz-drop.fish → zz.fish`),
a plain copy where symlinks aren't available. `--setup-completions
--uninstall` removes both.

Zsh handles this natively: the `#compdef zz zz-drop` line at the
top of `_zz` tells `compinit` to autoload the same completer for
both names, so no alias file is needed.

### Install-path matrix

- **Homebrew** (`brew install zz-drop/zz-drop/zz-drop`) — installs
  completion files into the standard cellar paths
  (`share/{bash-completion/completions,zsh/site-functions,
  fish/vendor_completions.d}`); `brew uninstall` reverses them.
  Brew, by policy, does not touch dotfiles. On Apple Silicon the
  cellar path isn't in zsh's default `fpath`, and a fresh macOS
  `.zshrc` typically doesn't call `compinit`, so the formula's
  `caveats` block points the operator at the two one-liners they
  need to add (`brew shellenv` + `autoload compinit`). Operators
  who'd rather have a delimited block written for them can run
  `zz --setup-completions` after install.
- **`curl | sh` installer** — drops binaries, then invokes
  `zz --setup-completions <shell>` so file + rc block land in one
  step. Bash is wired unconditionally regardless of `$SHELL`
  (containers, cron jobs and SSH non-login sessions often have
  `$SHELL` unset). zsh / fish wiring still gates on `$SHELL`
  pointing at the matching shell — target paths depend on user
  dotfile config (`ZDOTDIR`, fish completions dir), so dropping
  the file for users who don't run that shell would land it in
  an unexpected place.
- **`cargo install --git`** — no post-install hook fires, so run
  `zz --setup-completions` manually once.

### Scriptable mode

Both flags support `--json` and `--quiet`:

```sh
zz --setup-completions --json
# {"v":"1","event":"completions_setup","ts":"...","shell":"zsh", …}

zz --check-completions --quiet
# zsh:wired
```

Exit codes: `0` on success, `2` for usage errors, `12`
(`EXIT_COMPLETIONS_FAILED`) when the filesystem write fails or the
status check reports anything other than `wired`.

## zsh styling (built-in, override-friendly)

The SACS zsh script auto-applies a styling block on first
invocation: headed groups, menu-select on first ambiguous match,
filename colors, cyan section headers, SACS rank order. Every
zstyle is **scoped** to the `(zz|zz-drop)` command context, so
TAB behaviour for any other command (git, ls, kubectl, …) is
left untouched.

Each setting is wrapped in a `zstyle -m … || zstyle …` guard,
which means an explicit override in your `~/.zshrc` always wins
— no need to touch the script.

### Override examples

```zsh
# Pick a different header color
zstyle ':completion:*:*:(zz|zz-drop):*:descriptions' format '%F{green}[%d]%f'

# Surface SACS verbs above remote files
zstyle ':completion:*:*:(zz|zz-drop):*' tag-order \
    'verbs atomics remote-files remote-dirs local-files local-dirs help'

# Disable menu-select entirely
zstyle ':completion:*:*:(zz|zz-drop):*' menu no
```

### Disable the auto-styling

To opt out entirely (e.g., you want pure flat completion or are
debugging a zstyle conflict), set the env var **before** the
first invocation:

```zsh
export _ZZ_NO_AUTO_STYLE=1
```

The fall-through behaviour is the stock-zsh flat list, identical
to bash and fish.

### What gets applied (full list)

| Style | Default value | Purpose |
|---|---|---|
| `zmodload zsh/complist` | always loaded | Provides `menu-select` widget |
| `zle -C menu-select .menu-select _main_complete` | registered if not already present | Makes the widget invokable |
| `menu select=1` | first ambiguous match | Enter menu-select on TAB |
| `group-name ''` | each tag = own group | Section per `_describe -t <tag>` |
| `descriptions format` | `%F{cyan}[%d]%f` | Cyan bracketed header |
| `verbose yes` | descriptions visible | Show `value : description` |
| `sort false` | preserve SACS order | No alphabetical re-sort |
| `list-colors` | `$LS_COLORS` + `ma=01;36` | Filename colors + bold cyan selected |
| `tag-order` | `remote-files remote-dirs local-files local-dirs verbs atomics help` | Section order |

The completer already groups candidates by kind (`verb`,
`atomic`, `file_remote`, `dir_remote`, `file_local`, `dir_local`,
`help`) via `_describe -t <tag>`; the styling above gives those
tags their visual identity.

### Per-shell wrapper for `zz d <pattern>` (download glob)

`zz d` supports remote glob patterns server-side (see
[`commands.md`](./commands.md#path-semantics)), but every shell
runs its glob engine against the *local* filesystem first.
That creates an asymmetry between upload and download verbs:

- `zz s A*` works because the shell finds local files starting
  with `A`, expands them, and passes the concrete names to
  `zz s`. The binary never sees the `*`.
- `zz d Q*` fails (or downloads the wrong file) because the
  shell tries to match `Q*` against the local cwd, which is
  the wrong filesystem entirely.

To restore symmetry — `zz d <pattern>` should reach the binary
literally, then `zz d` expands it server-side against the
remote listing — use the per-shell wrapper below. Each wrapper
is **scoped to `zz`**: only the `zz` command word is
intercepted, every other command in the shell is untouched.

#### zsh

```zsh
# In ~/.zshrc (after the completion block).
# Skip zsh's local-fs glob for zz download verbs (d, dx, da, darx, …).
# Upload verbs (s, sa, sx, …) keep zsh's normal local expansion.
zz() {
    case "$1" in
        d|d[a-z]*) noglob command zz "$@" ;;
        *)         command zz "$@" ;;
    esac
}
```

#### bash

bash's default behaviour is more forgiving than zsh's: when a
glob has no local matches, bash passes the literal pattern to
the command. So `zz d Q*` typed in a cwd with no `Q*` files
already reaches `zz d` correctly under default bash. The wrapper
below handles the two remaining cases — local files happen to
match the pattern, or `shopt -s failglob` is set — by always
disabling the local glob for download verbs:

```bash
# In ~/.bashrc, anywhere after the `zz --setup-completions` block.
zz() {
    case "$1" in
        d|d[a-z]*)
            set -f
            command zz "$@"
            local rc=$?
            set +f
            return "$rc"
            ;;
        *)
            command zz "$@"
            ;;
    esac
}
```

Note: bash expands the wrapper's positional arguments *before*
calling the function body, so `set -f` only suppresses
expansion for *subsequent* commands in the function. To benefit
from it, callers should still quote ambiguous patterns
(`zz d 'Q*'`). If you prefer absolute safety over keystroke
ergonomics, the universally portable workaround is just
quoting: `zz d 'Q*'` works in every shell without any wrapper.

#### fish

fish errors on unmatched globs by default (similar to zsh). Add
a function to `~/.config/fish/functions/zz.fish`:

```fish
function zz --description 'zz wrapper: skip local glob on download verbs'
    switch $argv[1]
        case 'd' 'd?*'
            command zz (string escape -- $argv)
        case '*'
            command zz $argv
    end
end
```

`string escape` quotes each argument so fish's glob doesn't
expand it; the binary then receives the literal pattern and
expands remotely.

#### Universal fallback (no wrapper)

If you'd rather not install a wrapper at all, the workaround
that works in every shell is to quote the pattern at the call
site:

```sh
zz d 'Q*'
zz d 'backup/*.pdf'
```

Single quotes prevent every shell's glob engine from touching
the argument; the binary handles the expansion server-side.

**Before** (zsh without the zstyle block):

```
$ zz d <TAB>
AGENTS.md                                 -- download (raw bytes) · remote · 2.7 KiB
AN14880-android-porting.pdf               -- download (raw bytes) · remote · 11.0 MiB
CLAUDE.md                                 -- download (raw bytes) · remote · 1.4 KiB
…
```

**After** (zstyle block in `~/.zshrc`, scoped to `(zz|zz-drop)`):

```
$ zz d <TAB>
[remote file]
▌ AGENTS.md                                  download (raw bytes) · remote · 2.7 KiB
  AN14880-android-porting.pdf                download (raw bytes) · remote · 11.0 MiB
  CLAUDE.md                                  download (raw bytes) · remote · 1.4 KiB
  README.md                                  download (raw bytes) · remote · 4.2 KiB

[verb]
  dx                                         + decompress
  darx                                       + recursive + decompress
```

### What this does NOT do, by design

The block above is the **only** machinery `zz` recommends for
visual polish in zsh. Specifically, it is **not** any of:

- a plugin manager (oh-my-zsh, zinit, antigen, sheldon, zplug,
  znap)
- a third-party plugin (fzf-tab, zsh-syntax-highlighting,
  zsh-autosuggestions)
- an extra binary on `$PATH` (fzf, jq, gum, skim)
- a TAB rebind (`bindkey '^I' …`) or any other key binding
- a custom zle widget

Each of those would either intercept TAB globally (changing the
behaviour of *every* command, not just `zz`) or pull in
third-party software outside the user's control. The
`zstyle :zz|zz-drop:` scope above stays inside zsh's own
completion system and applies to nothing else.

## Architecture

```
shell (bash/zsh/fish)
    |
    | TAB
    v
inlined script (~30-40 lines)
    |
    | invokes:  zz __complete <prev_args> <current_word>
    v
zz binary
    |
    +-- state detector (S0-S4)         filesystem + agent socket probe
    +-- completion provider            exhaustive match on Command enum
    +-- agent bridge                   LIST_REMOTE through the local agent
    |
    | stdout: NDJSON (one candidate per line)
    v
script formats for the shell
    v
shell renders the dropdown in its native style
```

Zero external dependencies: NDJSON is hand-emitted (escaped quotes,
backslashes, control chars), there is no JSON parser involved on
either side, no `clap_complete`, no extra runtime.

`zz __complete` is hidden by the `__` prefix and intercepted in
`main.rs` *before* `parse_args` runs. Tokens like `--help`,
`-h`, `--completions`, `__complete` are matched as exact first
arguments only — anything else falls through to the grammar
parser, so files literally named `--foo` or `__bar` continue to
upload exactly like a file named `q` would (`zz ./q`).

## States and ranking

The detector reads three signals on every TAB:

- `profiles-local.zz` exists on disk?
- agent socket present?
- agent unlocked? (resolved with one cheap `Status` round-trip when
  the socket is present; skipped otherwise)

| State | Signals | Primary candidates (top → bottom) |
|---|---|---|
| **S0 fresh** | no usable container | `c` · `--help` |
| **S1 down** | container present, no socket | `z` · `c` · `q` · `w` · `f` |
| **S2 locked** | socket present, agent locked | `z` · `q` · `c` · `w` · `f` |
| **S3 ready** | socket present, agent unlocked | local files (newest first) · composite verbs · atomic verbs · `z` |
| **S4 ready, dual** | both containers usable | same as S3 plus `z local` / `z remote` |

The ranking is **fixed and deterministic**. No heuristics, no
machine learning. Same input always produces the same NDJSON; tests
snapshot ~20 contexts in `tests::sacs_complete::*` to keep
regressions visible.

In states S0–S2 the cursor context is ignored intentionally: the
operator cannot usefully upload until they unlock, so the dropdown
stays focused on the unlock/setup verbs even when the user starts
typing `s` or `d`.

In S3/S4 the second-positional rules kick in:

| Cursor context | Candidates |
|---|---|
| `zz <TAB>` | local files newest-first (rank 1..), then local directories with trailing `/` (rank 50..), then composite verbs (rank 100..). Path navigation works — `zz A<TAB>` → `Applications/`, then `zz Applications/<TAB>` lists its contents. |
| `zz s<TAB>` / `zz d<TAB>` | only verb expansions (M2 / M3) |
| `zz s <TAB>` | local files (rank 1..) **+ local directories** (rank 100..). Dirs end with `/`; a follow-up TAB descends into them — see "Path navigation" below |
| `zz s file1.md <TAB>` | more local files (rank 1..) and `dir_remote` "close as destination" (rank 50..) |
| `zz sa <TAB>` | local directories only |
| `zz sa src <TAB>` | remote-prefix candidates from the agent |
| `zz d <TAB>` | remote files (rank 1..) + remote directories (rank 50..) so the operator can navigate. Dir values carry a trailing `/`. Locked agent → empty list, no error. |
| `zz d notes.md <TAB>` | more remote files plus local-dir "close as destination" |
| `zz da <TAB>` | local directories (download destination) |
| `zz da ./out <TAB>` | remote-prefix candidates |

### Path navigation in local-file contexts

Whenever the dropdown lists local files or directories, the typed
prefix can include a path. SACS splits on the last `/`: it reads
the parent directory specified by the path part and matches the
trailing basename against entries there. Example:

- `zz s docs/<TAB>` → contents of `<cwd>/docs/`, with returned
  values like `docs/api.md` and `docs/internal/`.
- `zz s docs/ap<TAB>` → only entries in `<cwd>/docs/` whose
  basename starts with `ap`.

Directory candidates always carry a trailing `/`, so each TAB
either commits to a file or descends one level deeper. There is
no special path syntax to learn — it behaves like the standard
shell completion for `cat <path>`.

## NDJSON schema

One JSON object per line on stdout. Field order is fixed; the
output is sorted by `rank` ascending, then `value` ascending, so
snapshot tests cannot flap.

```
{"value": "...", "display": "...", "description": "...", "kind": "...", "rank": <u32>}
```

Fields:

- **`value`** — the literal text inserted into the buffer.
- **`display`** — the label rendered in the dropdown row, including
  the `zz <verb>` prefix to help the operator confirm what they are
  building.
- **`description`** — a short hint shown to the right of the
  display, when the shell supports it. May be empty.
- **`kind`** — one of:
  - `verb` — composite upload/download verb (`s`, `sx`, `sarx`, …)
  - `atomic` — single-word atomic verb (`z`, `q`, `w`, `c`, `f`)
  - `file_local` — a file in the operator's cwd
  - `dir_local` — a directory in the operator's cwd
  - `file_remote` — a remote file from the agent's `LIST_REMOTE`
  - `dir_remote` — a remote directory
  - `help` — link to the static help (`--help`)
  - `footer` — `+N more matches — keep typing to narrow ...`
- **`rank`** — sorting key. Lower numbers sort first.

## Agent endpoint `LIST_REMOTE`

Remote candidates come from a new agent endpoint added in protocol
version 1 (additive variant — the older request/response set still
round-trips unchanged). The wire-level details are documented in
[`agent-protocol.md`](./agent-protocol.md).

Operationally:

- **Cache TTL: 60 seconds.** A miss triggers one provider list
  call; a hit returns from RAM. The agent never persists this
  cache; it lives only between unlock and lock/TTL/exit.
- **Walk-to-root invalidation.** A successful upload to
  `<remote_root>/backup/snap/file.md` drops every cached entry for
  prefixes `backup/snap`, `backup`, and `None` (root), regardless
  of `kind_filter`. The CLI sends one `InvalidateRemote { prefix }`
  request after upload; the agent walks the chain on its side.
- **Locked → empty list.** With a locked agent the endpoint
  returns `Error(NotUnlocked)`; the completion treats it as "no
  remote candidates this time" and never surfaces an error.
- **Provider errors are NOT cached.** A transient 503 from
  Nextcloud / Drive / Graph is returned as `Error(Io { ... })` and
  dropped on the floor by the completer; the next TAB tries again.
- **Hard cap = 200 entries per response.** The agent enforces this
  at write time so the dropdown never receives more than the
  shell can render. The CLI in turn renders at most 50 candidates
  per dropdown position (`REMOTE_CANDIDATE_LIMIT` /
  `LOCAL_CANDIDATE_LIMIT`); spill is summarised by a `footer`
  row so the operator knows there is more material if they keep
  typing to narrow.

## Latency

Target: **under 50 ms perceived per TAB**, but with one big caveat.

- **Cache hit:** state probe + cache lookup + NDJSON render.
  Comfortably under 50 ms on Linux/macOS.
- **First miss against a real provider:** bounded by the provider's
  list call. Nextcloud PROPFIND is typically 50-200 ms; Google
  Drive `files.list` 100-500 ms; OneDrive Graph `/children`
  comparable. The agent serves the second TAB on the same prefix
  from cache for the next 60 s.
- **Agent locked / socket missing:** state probe is filesystem-only
  and stays under 5 ms. No network is touched.
- **Single-threaded accept loop:** the agent processes one request
  at a time (consistent with v1 posture). A long PROPFIND from one
  TAB will queue concurrent `Status` / `GetProfile` calls behind
  it. Acceptable for v1; the `docs/agent.md` lifecycle section
  documents the model.

## What SACS is not

- Not a REPL inside `zz`. There is no prompt, no readline, no
  history. The shell guides input; SACS only feeds the dropdown.
- Not AI / not heuristic. Same arguments → same NDJSON.
- Does not change `zz <file>` default output. A successful upload
  still prints `uploaded ...` with no trailing tip — the
  completion is purely a discovery surface.
- Does not bypass the parser. The grammar in `cli/parser.rs` is
  still the single source of truth; the completion provider
  exhaustive-matches `Command` so any future grammar change must
  update the suggestions.
- Does not include filename matching at invocation time
  (`zz d read` → `readme.md`). That idea operates on the resolved
  command, not on the dropdown.

## Known limitations (v1)

- **No inflight dedup.** A user typing fast may trigger several
  concurrent `LIST_REMOTE` requests for the same prefix on a cold
  cache. The agent serves them sequentially; the second one
  completes against the warm cache. Acceptable in practice.
- **No mtime in remote candidates yet.** The wire schema carries
  `mtime_secs: Option<u64>` but the agent currently always emits
  `None`. Provider integrations can populate this without a
  protocol bump.
- **bash basic** (no `bash-completion` v2) decays to a flat list
  without per-row descriptions. zsh groups by kind via
  `_describe -t <tag>` (and styles further with the optional
  block in `## zsh styling`); fish renders the full layout
  natively.
- **PowerShell, nushell, elvish are not supported.**
- **No "drill into a verb" UX.** Once the operator is inside the
  menu-select dropdown of `zz <TAB>` and arrows down to e.g. the
  `s` row, pressing TAB *commits* `s` (zsh's standard menu-select
  behaviour) instead of expanding it into its modifier variants
  (`sa`, `sx`, `sarx`). Today all variants are already listed
  flat in `zz <TAB>` next to `s`, so the operator can arrow once
  more to reach the desired form. A genuine "expand the
  highlighted verb" gesture would need a custom zle widget that
  re-invokes SACS with the highlighted token as a synthetic
  prefix, which is out of scope for v1.

## Privacy

Snapshots used in tests use only a fixed sanitised identifier set:
`casa-nc`, `cloud.example.org`, `zz-drop`, `alice@example.org`,
and a small filename pool (`readme.md`, `notes.txt`, `draft.md`,
`changelog.md`, `benchmark.log`, `file1.md`, `file2.md`,
`snapshot.tar.zst`). The
`tests::no_secret_or_remote_host_*` lock tests refuse real-looking
emails or token-shaped strings in any emitted candidate.

The remote names returned by `LIST_REMOTE` flow through the
dropdown the same way they flow through `zz d <name>` today — they
are not encrypted in v1 (consistent with the rest of the
filename surface).
