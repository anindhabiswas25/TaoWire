#!/usr/bin/env bash
# The project's Go toolchain and tools (spec 11.4, D23, G5-3). The one place the
# Go, staticcheck and govulncheck versions are pinned.
#
# The justfile never relies on whatever `go`, `staticcheck` or `govulncheck`
# happens to be on PATH: a host Go or an old ~/go/bin tool would make the gate
# pass on the wrong versions without saying so.
#
#   go_tools.sh sdk-path     print the SDK directory (the justfile puts its bin/ on PATH)
#   go_tools.sh ensure-sdk   check the SDK is the pinned Go; exit 2 otherwise
#   go_tools.sh ensure       ensure-sdk, then check the tools (module version and the Go
#                            they were built with); build missing or stale tools; exit 2
#                            with a clear message when that is not possible
#   go_tools.sh build        build the pinned tools into .tools/go/bin (`just go-tools`)
#   go_tools.sh run TOOL ... run TOOL from .tools/go/bin (the justfile runs `ensure` first)
#
# Settings (environment):
#   TAOWIRE_GO_SDK   default ~/sdk/go1.26.10
set -euo pipefail
export GOTOOLCHAIN=local

GO_VERSION="go1.26.10"
STATICCHECK_VERSION="v0.8.2"
GOVULNCHECK_VERSION="v1.9.0"

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_sdk="${TAOWIRE_GO_SDK:-$HOME/sdk/$GO_VERSION}"
go_bin="$go_sdk/bin/go"
tools_dir="$repo_dir/.tools/go/bin"

fail() {
    echo "error: $*" >&2
    exit 2
}

check_sdk() {
    if [ ! -x "$go_bin" ]; then
        fail "project Go SDK not found at $go_sdk (TAOWIRE_GO_SDK).
  install it (user-local, D23): go install golang.org/dl/$GO_VERSION@latest && $GO_VERSION download"
    fi
    local found
    found="$("$go_bin" env GOVERSION)"
    if [ "$found" != "$GO_VERSION" ]; then
        fail "$go_bin is $found, the project pins $GO_VERSION (set TAOWIRE_GO_SDK to a $GO_VERSION SDK)"
    fi
}

# Prints what is wrong with one tool, or nothing. Reads the build info
# (`go version -m`): no network, and the tool is not run.
tool_problem() {
    local name="$1" module="$2" version="$3" info built
    local bin="$tools_dir/$name"
    if [ ! -x "$bin" ]; then echo "$name missing from $tools_dir"; return; fi
    if ! info="$("$go_bin" version -m "$bin" 2>/dev/null)"; then
        echo "$name has no Go build info"
        return
    fi
    built="$(awk 'NR == 1 {print $2}' <<<"$info")"
    if [ "$built" != "$GO_VERSION" ]; then
        echo "$name was built with $built, not $GO_VERSION"
    elif ! grep -qE "^[[:space:]]+mod[[:space:]]+$module[[:space:]]+$version([[:space:]]|$)" <<<"$info"; then
        echo "$name is not $module $version"
    fi
}

tools_problem() {
    tool_problem staticcheck honnef.co/go/tools "$STATICCHECK_VERSION"
    tool_problem govulncheck golang.org/x/vuln "$GOVULNCHECK_VERSION"
}

# Chained with && on purpose: `ensure` calls this inside `if`, where `set -e` does not apply.
install_tools() {
    mkdir -p "$tools_dir" &&
        GOBIN="$tools_dir" "$go_bin" install "honnef.co/go/tools/cmd/staticcheck@$STATICCHECK_VERSION" &&
        GOBIN="$tools_dir" "$go_bin" install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
}

ensure() {
    check_sdk
    local problem
    problem="$(tools_problem)"
    if [ -n "$problem" ]; then
        echo "go tools: ${problem//$'\n'/; }; building them (just go-tools)"
        if ! install_tools; then
            fail "could not build the Go tools into $tools_dir (offline or module proxy unreachable?).
  run \`just go-tools\` when the network is available; the gate does not fall back to tools on PATH"
        fi
        problem="$(tools_problem)"
        [ -z "$problem" ] || fail "go tools still wrong after building: $problem"
    fi
    echo "go tools ok: $GO_VERSION, staticcheck $STATICCHECK_VERSION, govulncheck $GOVULNCHECK_VERSION ($tools_dir)"
}

case "${1:-}" in
    sdk-path) echo "$go_sdk" ;;
    ensure-sdk) check_sdk && echo "go sdk ok: $GO_VERSION ($go_sdk)" ;;
    ensure) ensure ;;
    build) check_sdk && install_tools && "$go_bin" version ;;
    run)
        case "${2:-}" in
            staticcheck | govulncheck) tool="$tools_dir/$2"; shift 2; exec "$tool" "$@" ;;
            *) echo "usage: $0 run staticcheck|govulncheck [args...]" >&2; exit 64 ;;
        esac
        ;;
    *) echo "usage: $0 sdk-path|ensure-sdk|ensure|build|run TOOL [args...]" >&2; exit 64 ;;
esac
