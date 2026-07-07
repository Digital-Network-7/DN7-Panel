#!/usr/bin/env bash
#
# DN7 Panel — quick installer.
#
# Downloads the latest static binary, SPEED-TESTING GitHub / ghfast.top /
# ghproxy.net (~5s each, by average throughput — not first-byte latency) to pick
# the fastest source, shows a download progress bar, then launches first-run
# setup. One-line install:
#
#   curl -fsSL https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
#
# Behind a restrictive network, fetch the script through a mirror (the binary is
# still speed-raced across all three regardless of which mirror served the script):
#
#   curl -fsSL https://ghfast.top/https://github.com/Digital-Network-7/DN7-Panel/raw/main/install.sh | sudo bash
#
set -u

REPO="Digital-Network-7/DN7-Panel"
BASE_PATH="/$REPO"
REL_PATH="$BASE_PATH/releases/latest/download/releases.json"

# Download lines: GitHub direct + two URL-prefix proxies (a proxy prefixes the
# whole https://github.com/… URL — the scheme the panel's self-updater uses).
S1="https://github.com"
S2="https://ghfast.top/https://github.com"
S3="https://ghproxy.net/https://github.com"

c_g=''; c_b=''; c_r=''; c_d=''
if [ -t 1 ]; then c_g=$'\033[32m'; c_b=$'\033[1m'; c_r=$'\033[31m'; c_d=$'\033[0m'; fi
say()  { printf '%s\n' "  $*"; }
ok()   { printf '%s\n' "  ${c_g}✓${c_d} $*"; }
die()  { printf '%s\n' "${c_r}DN7 安装失败 / install failed:${c_d} $*" >&2; exit 1; }
rule() { printf '  --------------------------------------------------------\n'; }
hostof() { printf '%s' "$1" | sed 's#https://##; s#/https:.*##'; }
# bytes/sec → human-readable transfer speed.
hspeed() { awk -v b="$1" 'BEGIN{ if(b>=1048576) printf "%.1f MiB/s", b/1048576; else if(b>=1024) printf "%.0f KiB/s", b/1024; else printf "%d B/s", b }'; }

# --- downloader (curl preferred, wget fallback) ----------------------------
if command -v curl >/dev/null 2>&1; then
  USE_CURL=1
  qfetch()      { curl -fsSL --connect-timeout 6 --max-time 60 "$1" -o "$2"; }
  # Sustained-throughput probe: pull up to ~10 MiB (or 5s, whichever first) and
  # report the AVERAGE speed curl measured (bytes/sec) + the HTTP status — a far
  # better predictor of real download time than first-byte latency. curl prints
  # the -w line even when `--max-time` trips (a slow-but-working source keeps its
  # partial-transfer speed) or on a connect failure (speed 0, code 000), so no
  # `|| echo` fallback is needed — that would double the output and corrupt it.
  speed_probe() { curl -sL --connect-timeout 5 --max-time 5 -r 0-10485759 -o /dev/null -w '%{speed_download} %{http_code}' "$1" 2>/dev/null; }
  dl_progress() { curl -fL --connect-timeout 8 --max-time 1800 --progress-bar "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  USE_CURL=''
  qfetch()      { wget -q -O "$2" --timeout=60 --tries=2 "$1"; }
  speed_probe() { echo '0 000'; }   # wget can't cheaply report throughput → skip the race
  dl_progress() { wget -q --show-progress -O "$2" --timeout=1800 --tries=2 "$1"; }
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

# --- resolve the latest version + build (tiny index; first working source) --
REL=$(mktemp); have=''
for base in "$S1" "$S2" "$S3"; do
  if qfetch "$base$REL_PATH" "$REL" 2>/dev/null && grep -q '"product"' "$REL" 2>/dev/null; then have=1; break; fi
done
[ -n "$have" ] || die "无法获取版本信息 / could not fetch the release index"
VERSION=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]*"' "$REL" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
BUILD=$(grep -oE '"build"[[:space:]]*:[[:space:]]*"?[0-9]+"?' "$REL" | head -1 | sed -E 's/[^0-9]//g')
rm -f "$REL"
[ -n "$VERSION" ] && [ -n "$BUILD" ] || die "版本信息解析失败 / could not parse the release index"
ASSET="dn7-panel-linux-${ARCH}-v${VERSION}"
BIN_PATH="$BASE_PATH/releases/download/b${BUILD}/${ASSET}"
ok "版本 / version: Phanes ${VERSION} (build ${BUILD}) · ${ARCH}"

# --- speed race: measure each source's ~5s average throughput --------------
d=$(mktemp -d)
if [ -n "$USE_CURL" ]; then
  say "正在测速选择最快下载源(每个源约 5 秒)/ speed-testing each source (~5s avg) …"
  i=0
  for base in "$S1" "$S2" "$S3"; do
    host=$(hostof "$base")
    res=$(speed_probe "$base$BIN_PATH")
    spd=$(printf '%s' "$res" | awk '{printf "%d", $1}')
    code=$(printf '%s' "$res" | awk '{print $2}')
    case "$code" in
      200 | 206) ok "  ${host}: $(hspeed "$spd")"; printf '%s %s\n' "$spd" "$base" >"$d/$i" ;;
      *) say "  ${host}: 不可达 / unreachable (HTTP ${code})" ;;
    esac
    i=$((i + 1))
  done
  # Fastest throughput first; ties/failures fall through to the next source.
  ORDER=$(sort -rn "$d"/* 2>/dev/null | awk '{print $2}')
else
  ORDER="$S1
$S2
$S3"   # wget path: no throughput probe, just try in order
fi
rm -rf "$d"
[ -n "$ORDER" ] || die "所有源测速失败 / no source passed the speed test"
best=$(printf '%s\n' "$ORDER" | head -1)
ok "最快源 / fastest: $(hostof "$best")"

# --- download from the fastest (with a progress bar; fallback by speed) -----
OUT=$(mktemp); got=''
for base in $ORDER; do
  host=$(hostof "$base")
  say "下载中 / downloading via ${host} …"
  if dl_progress "$base$BIN_PATH" "$OUT" && [ -s "$OUT" ]; then got=1; break; fi
  say "  ${host} 下载失败,换下一个源 / download failed, trying the next source"
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
