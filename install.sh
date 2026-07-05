#!/usr/bin/env bash
#
# DN7 Panel — quick installer.
#
# Downloads the latest static binary, racing GitHub / ghfast.top / ghproxy.net for
# the fastest source, then launches first-run setup. One-line install:
#
#   curl -fsSL https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
#
# Behind a restrictive network, fetch the script through a mirror (the binary is
# raced across all three regardless of which mirror served the script):
#
#   curl -fsSL https://ghfast.top/https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
#
set -u

REPO="Digital-Network-7/DN7-Panel"
BASE_PATH="/$REPO"
REL_PATH="$BASE_PATH/releases/latest/download/releases.json"

# Download lines, raced fastest-first: GitHub direct + two URL-prefix proxies.
# A proxy prefixes the whole https://github.com/… URL — the same scheme the
# panel's own self-updater uses (src/infra/support/fetch/mirror.rs).
S1="https://github.com"
S2="https://ghfast.top/https://github.com"
S3="https://ghproxy.net/https://github.com"

c_g=''; c_b=''; c_r=''; c_d=''
if [ -t 1 ]; then c_g=$'\033[32m'; c_b=$'\033[1m'; c_r=$'\033[31m'; c_d=$'\033[0m'; fi
say()  { printf '%s\n' "  $*"; }
ok()   { printf '%s\n' "  ${c_g}✓${c_d} $*"; }
die()  { printf '%s\n' "${c_r}DN7 安装失败 / install failed:${c_d} $*" >&2; exit 1; }
rule() { printf '  --------------------------------------------------------\n'; }

# --- downloader (curl preferred, wget fallback) ----------------------------
if command -v curl >/dev/null 2>&1; then
  probe() {
    if t=$(curl -o /dev/null -sL -w '%{time_total}' --connect-timeout 4 --max-time 15 "$1" 2>/dev/null); then
      awk "BEGIN{printf \"%d\", $t*1000}"
    else printf '%s' 999000; fi
  }
  fetch() { curl -fSL --connect-timeout 8 --max-time 1800 "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  probe() {
    s=$(date +%s%N 2>/dev/null || echo 0)
    if wget -q -O /dev/null --timeout=15 --tries=1 "$1" 2>/dev/null; then
      e=$(date +%s%N 2>/dev/null || echo 0); echo $(( (e - s) / 1000000 ))
    else echo 999000; fi
  }
  fetch() { wget -q -O "$2" --timeout=1800 --tries=2 "$1"; }
else
  die "需要 curl 或 wget / need curl or wget"
fi

# --- environment -----------------------------------------------------------
[ "$(uname -s)" = "Linux" ] || die "DN7 Panel 仅支持 Linux / Linux only"
case "$(uname -m)" in
  x86_64 | amd64)  ARCH="x86_64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  *) die "不支持的架构 / unsupported architecture: $(uname -m)" ;;
esac

rule
printf '  %sDN7 Panel%s · 快速安装 / quick install\n' "$c_b" "$c_d"
rule

# --- race the sources, fastest-first ---------------------------------------
say "正在竞速选择下载源 / racing sources: github · ghfast.top · ghproxy.net …"
d=$(mktemp -d)
i=0
for base in "$S1" "$S2" "$S3"; do
  ( printf '%s %s\n' "$(probe "$base$REL_PATH")" "$base" >"$d/$i" ) &
  i=$((i + 1))
done
wait
ORDER=$(sort -n "$d"/* 2>/dev/null | awk '{print $2}')
rm -rf "$d"
[ -n "$ORDER" ] || ORDER="$S1
$S2
$S3"
fastest=$(printf '%s\n' "$ORDER" | head -1)
ok "最快源 / fastest: $(printf '%s' "$fastest" | sed 's#https://##; s#/https:.*##')"

# --- resolve the latest version + build ------------------------------------
REL=$(mktemp)
have=''
for base in $ORDER; do
  if fetch "$base$REL_PATH" "$REL" 2>/dev/null && grep -q '"product"' "$REL" 2>/dev/null; then have="$base"; break; fi
done
[ -n "$have" ] || die "无法获取版本信息 / could not fetch the release index"
VERSION=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$REL" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
BUILD=$(grep -oE '"build"[[:space:]]*:[[:space:]]*"?[0-9]+"?' "$REL" | head -1 | sed -E 's/[^0-9]//g')
rm -f "$REL"
[ -n "$VERSION" ] && [ -n "$BUILD" ] || die "版本信息解析失败 / could not parse the release index"
ASSET="dn7-panel-linux-${ARCH}-v${VERSION}"
BIN_PATH="$BASE_PATH/releases/download/b${BUILD}/${ASSET}"
ok "版本 / version: Phanes ${VERSION} (build ${BUILD}) · ${ARCH}"

# --- download the binary (fastest-first, with fallback) --------------------
OUT=$(mktemp)
got=''
for base in $ORDER; do
  host=$(printf '%s' "$base" | sed 's#https://##; s#/https:.*##')
  say "下载中 / downloading via ${host} …"
  if fetch "$base$BIN_PATH" "$OUT" 2>/dev/null && [ -s "$OUT" ]; then got="$base"; break; fi
  say "  ${host} 不可用,尝试下一个 / unavailable, trying the next source"
done
[ -n "$got" ] || die "所有源下载失败 / download failed from every source"
chmod +x "$OUT" 2>/dev/null || true
ok "已下载 / downloaded ($(wc -c <"$OUT" | awk '{printf "%.1f MiB", $1/1048576}'))"

# --- run first-run setup ---------------------------------------------------
rule
say "启动 DN7 Panel(安装到 /var/dn7/panel 并进入初始化向导)"
say "Launching DN7 Panel (installs to /var/dn7/panel, then the setup wizard)"
rule

# DN7_INSTALL_NO_RUN=1 stops here (download only) instead of launching setup.
if [ "${DN7_INSTALL_NO_RUN:-}" = "1" ]; then
  ok "已下载,未运行 / downloaded, not run (DN7_INSTALL_NO_RUN=1): $OUT"
  exit 0
fi

if [ "$(id -u)" -eq 0 ]; then RUN="$OUT"; else RUN="sudo $OUT"; fi
if [ -e /dev/tty ]; then
  # Reattach the terminal so the interactive setup wizard works even when this
  # script arrived over a pipe (curl … | sudo bash).
  exec $RUN </dev/tty
else
  say "未检测到交互终端 / no interactive terminal detected."
  say "二进制已就绪 / the binary is ready at: $OUT"
  say "请在终端运行以完成初始化 / run in a terminal to finish setup:  ${c_b}sudo $OUT${c_d}"
fi
