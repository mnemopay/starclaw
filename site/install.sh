#!/usr/bin/env bash
# StarClaw installer for macOS and Linux:   curl -fsSL https://starclaw.dev/install.sh | bash
#
# - No sudo, nothing outside your home directory.
# - Uses your Node if it is >= 25.9; otherwise downloads the official Node 25.9.0 build from nodejs.org and checks it
#   against nodejs.org's SHASUMS256.txt before using it.
# - Installs StarClaw from npm (production dependencies only) into ~/.starclaw-runtime and adds two commands to
#   ~/.local/bin: `starclaw` and `starclaw-app` (opens the console in your browser; first run = guided model setup).
# - Your data (keys, audit log, workspace) lives in ~/.starclaw-app and is never touched by reinstalling.
#
# Options (environment variables):
#   STARCLAW_VERSION   npm version or tag to install (default: next)
#   STARCLAW_PACKAGE   install from this local .tgz instead of npm (CI / testing)
#   STARCLAW_PREFIX    where the runtime goes (default: ~/.starclaw-runtime)
#   STARCLAW_BIN_DIR   where the commands go (default: ~/.local/bin)
# Uninstall: rm -rf ~/.starclaw-runtime ~/.local/bin/starclaw ~/.local/bin/starclaw-app   (keeps ~/.starclaw-app)
set -euo pipefail

NODE_VERSION="25.9.0"
VERSION="${STARCLAW_VERSION:-next}"
PREFIX="${STARCLAW_PREFIX:-$HOME/.starclaw-runtime}"
BIN_DIR="${STARCLAW_BIN_DIR:-$HOME/.local/bin}"

say() { printf '\033[1mstarclaw:\033[0m %s\n' "$*"; }
die() { printf '\033[31mstarclaw: %s\033[0m\n' "$*" >&2; exit 1; }

[ "$(id -u)" = "0" ] && die "do not run this as root; it installs into your home directory only"
case "$(uname -s)" in Darwin) os=darwin ;; Linux) os=linux ;; *) die "unsupported OS $(uname -s) (Windows: use the installer from https://github.com/mnemopay/starclaw/releases)" ;; esac
case "$(uname -m)" in x86_64|amd64) arch=x64 ;; arm64|aarch64) arch=arm64 ;; *) die "unsupported CPU $(uname -m)" ;; esac
command -v curl >/dev/null || die "curl is required"
command -v tar >/dev/null || die "tar is required"
if command -v sha256sum >/dev/null; then sha() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$1" | cut -d' ' -f1; }
else die "sha256sum or shasum is required"; fi

mkdir -p "$PREFIX" "$BIN_DIR"
NODE_BIN=""
# Native dependencies are installed for the Node that runs npm, so the Node we install with is the Node StarClaw runs on.
if command -v node >/dev/null && node -e 'const [a,b]=process.versions.node.split(".").map(Number);process.exit(a>25||(a===25&&b>=9)?0:1)' 2>/dev/null; then
  NODE_BIN="$(command -v node)"
  say "using your Node $(node --version) ($NODE_BIN)"
else
  name="node-v${NODE_VERSION}-${os}-${arch}"
  dest="$PREFIX/node"
  if [ -x "$dest/bin/node" ] && [ "$("$dest/bin/node" --version)" = "v${NODE_VERSION}" ]; then
    say "Node ${NODE_VERSION} already present"
  else
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    say "downloading Node ${NODE_VERSION} (${os}-${arch}) from nodejs.org"
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/${name}.tar.gz" -o "$tmp/node.tar.gz"
    curl -fsSL "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" -o "$tmp/SHASUMS256.txt"
    want="$(grep "  ${name}.tar.gz\$" "$tmp/SHASUMS256.txt" | cut -d' ' -f1)"
    [ -n "$want" ] || die "${name}.tar.gz is not listed in nodejs.org's SHASUMS256.txt"
    got="$(sha "$tmp/node.tar.gz")"
    [ "$got" = "$want" ] || die "Node download checksum mismatch (got $got, nodejs.org lists $want); nothing installed"
    say "Node checksum OK ($got)"
    rm -rf "$dest" && mkdir -p "$dest"
    tar -xzf "$tmp/node.tar.gz" -C "$dest" --strip-components=1
  fi
  NODE_BIN="$dest/bin/node"
fi
# Dependency install scripts (e.g. better-sqlite3's prebuild-install) run `node` from PATH: make it ours.
export PATH="$(dirname "$NODE_BIN"):$PATH"
NPM_CLI="$(dirname "$NODE_BIN")/../lib/node_modules/npm/bin/npm-cli.js"
[ -f "$NPM_CLI" ] || NPM_CLI="$(dirname "$(readlink -f "$NODE_BIN" 2>/dev/null || echo "$NODE_BIN")")/../lib/node_modules/npm/bin/npm-cli.js"
[ -f "$NPM_CLI" ] || die "could not find npm next to $NODE_BIN"

app="$PREFIX/app"
mkdir -p "$app"
[ -f "$app/package.json" ] || printf '{ "private": true }\n' > "$app/package.json"
spec="starclaw@${VERSION}"
[ -n "${STARCLAW_PACKAGE:-}" ] && spec="$STARCLAW_PACKAGE"
say "installing $spec"
"$NODE_BIN" "$NPM_CLI" install --prefix "$app" --omit=dev --omit=optional --no-audit --no-fund --loglevel=error "$spec" >/dev/null
CLI="$app/node_modules/starclaw/dist/cli.js"
[ -f "$CLI" ] || die "install finished but $CLI is missing"

write_cmd() { # name, extra args
  cat > "$BIN_DIR/$1" <<EOF
#!/bin/sh
exec "$NODE_BIN" "$CLI" $2 "\$@"
EOF
  chmod 755 "$BIN_DIR/$1"
}
write_cmd starclaw ""
write_cmd starclaw-app "app"

say "installed StarClaw $("$NODE_BIN" "$CLI" --version) with Node $("$NODE_BIN" --version)"
case ":$PATH:" in
  *":$BIN_DIR:"*) say "start it with:  starclaw-app" ;;
  *) say "start it with:  $BIN_DIR/starclaw-app"; say "(add $BIN_DIR to your PATH to type just: starclaw-app)" ;;
esac
