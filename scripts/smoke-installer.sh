#!/usr/bin/env bash
# smoke-installer.sh — exercise the published curl installer end-to-end
# inside an Alpine 3.19 container. Verifies binary placement, version
# output, completion file install per shell, and ~/.zshrc auto-populate
# behaviour across the four scenarios the patch-installer workflow handles.
#
# Usage:
#   ./scripts/smoke-installer.sh                  # latest published pre-release
#   ./scripts/smoke-installer.sh v0.0.1-pre.11    # explicit tag
#   VERSION=v0.0.1-pre.11 ./scripts/smoke-installer.sh
#
# Exits 0 on full PASS, non-zero on any FAIL. Intended to be invoked
# from CI (.github/workflows/smoke-installer.yml) and from a developer
# laptop with docker / OrbStack / Podman available.

set -eu

VERSION="${1:-${VERSION:-}}"
if [ -z "$VERSION" ]; then
    # Latest published release (any kind: stable, prerelease).
    # Stable releases became the norm from 0.9.0 onward; the earlier
    # filter on `prerelease==true` excluded them and left VERSION empty
    # once the project went stable.
    VERSION=$(gh api 'repos/zz-drop/zz-drop/releases/latest' \
        --jq '.tag_name' 2>/dev/null) || {
        echo "smoke: unable to resolve VERSION (gh api failed); pass it explicitly"
        exit 2
    }
fi

INSTALLER_URL="https://github.com/zz-drop/zz-drop/releases/download/${VERSION}/zz-drop-installer.sh"
echo "smoke: VERSION=${VERSION}"
echo "smoke: INSTALLER_URL=${INSTALLER_URL}"
echo

DOCKER="${DOCKER:-docker}"
command -v "$DOCKER" >/dev/null 2>&1 || {
    echo "smoke: '$DOCKER' not on PATH (set DOCKER= or install OrbStack / Docker)"
    exit 2
}

PASS=0
FAIL=0

# Run a scenario: take a name + the inside-container script.
# Asserts via grep on docker output. Bumps PASS/FAIL.
run_scenario() {
    name="$1"
    script="$2"
    expect="$3"
    echo "── ${name}"
    out=$("$DOCKER" run --rm \
        -e VERSION="$VERSION" \
        -e INSTALLER_URL="$INSTALLER_URL" \
        alpine:3.19 sh -c "$script" 2>&1)
    if printf '%s\n' "$out" | grep -qE "$expect"; then
        echo "  PASS"
        PASS=$((PASS + 1))
    else
        echo "  FAIL — expected pattern: $expect"
        echo "  --- container output (last 30 lines) ---"
        printf '%s\n' "$out" | tail -30 | sed 's/^/    /'
        FAIL=$((FAIL + 1))
    fi
}

# 1. Bash: install + verify binaries + verify completion file lands at XDG path
run_scenario "bash: install + completion" '
    set -e
    apk add --no-cache curl ca-certificates bash > /dev/null 2>&1
    SHELL=/bin/bash sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /tmp/log 2>&1
    test -x ~/.local/bin/zz-drop || { echo "BIN MISSING"; cat /tmp/log; exit 1; }
    test -x ~/.local/bin/zz-tui || { echo "ZZ-TUI MISSING"; exit 1; }
    test -L ~/.local/bin/zz || { echo "ZZ SYMLINK MISSING"; exit 1; }
    test -f ~/.local/share/bash-completion/completions/zz-drop || {
        echo "BASH COMPLETION FILE MISSING"; cat /tmp/log; exit 1
    }
    head -1 ~/.local/share/bash-completion/completions/zz-drop | grep -q "zz-drop bash completion" \
        || { echo "BASH COMPLETION CONTENT WRONG"; exit 1; }
    echo "ALL_GOOD"
' "ALL_GOOD"

# 2. Bash: --version on all three binaries returns the expected tag
run_scenario "bash: --version on zz / zz-drop / zz-tui" '
    set -e
    apk add --no-cache curl ca-certificates > /dev/null 2>&1
    SHELL=/bin/bash sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /dev/null 2>&1
    expected="${VERSION#v}"
    for b in zz zz-drop zz-tui; do
        out=$(~/.local/bin/$b --version)
        echo "$out" | grep -q "$expected" || {
            echo "VERSION MISMATCH for $b: got [$out], expected to contain [$expected]"; exit 1
        }
    done
    echo "ALL_GOOD"
' "ALL_GOOD"

# 3. Zsh: install + auto-populate fresh .zshrc with marker + fpath + compinit
run_scenario "zsh: auto-populate fresh .zshrc" '
    set -e
    apk add --no-cache curl ca-certificates zsh > /dev/null 2>&1
    rm -f ~/.zshrc
    SHELL=/bin/zsh sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /dev/null 2>&1
    test -f ~/.zfunc/_zz || { echo "ZSH COMPLETION FILE MISSING"; exit 1; }
    test -f ~/.zshrc || { echo "ZSHRC NOT CREATED"; exit 1; }
    grep -q "zz-drop SACS" ~/.zshrc || { echo "MARKER MISSING"; cat ~/.zshrc; exit 1; }
    grep -q "fpath=" ~/.zshrc || { echo "FPATH MISSING"; cat ~/.zshrc; exit 1; }
    grep -q "compinit" ~/.zshrc || { echo "COMPINIT MISSING"; cat ~/.zshrc; exit 1; }
    echo "ALL_GOOD"
' "ALL_GOOD"

# 4. Zsh: framework-aware — when oh-my-zsh signature present, only fpath added (no compinit)
run_scenario "zsh: framework-aware (oh-my-zsh detected → only fpath)" '
    set -e
    apk add --no-cache curl ca-certificates zsh > /dev/null 2>&1
    cat > ~/.zshrc <<EOF
# my custom config
source ~/.oh-my-zsh/oh-my-zsh.sh
EOF
    SHELL=/bin/zsh sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /dev/null 2>&1
    grep -q "framework detected (oh-my-zsh)" ~/.zshrc || {
        echo "FRAMEWORK MARKER MISSING"; cat ~/.zshrc; exit 1
    }
    grep -q "fpath=" ~/.zshrc || { echo "FPATH MISSING"; exit 1; }
    # We do NOT add compinit here because the framework owns it
    grep -q "autoload -U compinit" ~/.zshrc && {
        echo "COMPINIT WAS ADDED (should not — framework owns it)"; cat ~/.zshrc; exit 1
    }
    echo "ALL_GOOD"
' "ALL_GOOD"

# 5. Zsh: idempotency — re-running the installer with marker present must NOT re-append
run_scenario "zsh: re-run is no-op when marker present" '
    set -e
    apk add --no-cache curl ca-certificates zsh > /dev/null 2>&1
    rm -f ~/.zshrc
    SHELL=/bin/zsh sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /dev/null 2>&1
    sha_before=$(sha256sum ~/.zshrc | cut -d" " -f1)
    SHELL=/bin/zsh sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /dev/null 2>&1
    sha_after=$(sha256sum ~/.zshrc | cut -d" " -f1)
    [ "$sha_before" = "$sha_after" ] || {
        echo "ZSHRC CHANGED ON RE-RUN"; diff <(echo "$sha_before") <(echo "$sha_after"); exit 1
    }
    echo "ALL_GOOD"
' "ALL_GOOD"

# 6. Fish: completion file lands in fish standard auto-load path
run_scenario "fish: install + completion" '
    set -e
    apk add --no-cache curl ca-certificates fish > /dev/null 2>&1
    SHELL=/usr/bin/fish sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /dev/null 2>&1
    test -f ~/.config/fish/completions/zz.fish || {
        echo "FISH COMPLETION MISSING"; exit 1
    }
    head -1 ~/.config/fish/completions/zz.fish | grep -q "fish completion" \
        || { echo "FISH COMPLETION CONTENT WRONG"; exit 1; }
    echo "ALL_GOOD"
' "ALL_GOOD"

# 7. SHELL unset: graceful skip, no completion install attempted
run_scenario "no SHELL: graceful skip (binaries still installed)" '
    set -e
    apk add --no-cache curl ca-certificates > /dev/null 2>&1
    unset SHELL
    sh -c "curl -fsSL ${INSTALLER_URL} | sh" > /tmp/log 2>&1
    test -x ~/.local/bin/zz-drop || { echo "BIN MISSING"; exit 1; }
    grep -q "completion: \$SHELL not set; skip" /tmp/log || {
        echo "EXPECTED skip MESSAGE NOT FOUND"; cat /tmp/log; exit 1
    }
    test ! -f ~/.local/share/bash-completion/completions/zz-drop || {
        echo "BASH COMPLETION INSTALLED ANYWAY"; exit 1
    }
    echo "ALL_GOOD"
' "ALL_GOOD"

echo
echo "════════════════════════════════════"
echo " ${PASS} PASS / ${FAIL} FAIL of $((PASS + FAIL)) scenarios"
echo "════════════════════════════════════"
exit "$FAIL"
