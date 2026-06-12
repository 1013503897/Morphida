#!/usr/bin/env bash
# Connect to an already-running Morphida frida-server on an adb device, with a
# hard client/server version assertion up front.
#
# This is the "make a frida session actually work" primitive that other projects
# (and AI sessions) shell out to. It does NOT open the cloud-phone tunnel — that
# needs the at-xx MCP (see the `jw-adb` skill / phone_open_adb). Pass the adb
# serial it returns (e.g. 127.0.0.1:5619) via -s.
#
# What it does, in order:
#   1. verify the device is reachable + rooted
#   2. read the server version straight off the (renamed) binary: `<bin> --version`
#   3. read the local client version: `frida --version`
#   4. ASSERT they are equal — frida refuses to talk across a version gap, so we
#      fail loudly here with the exact `pip install frida==<ver>` to run, instead
#      of letting the caller hit a cryptic handshake error later
#   5. ensure the daemon is running (start it if not: setenforce 0 + nohup)
#   6. adb forward <local-port> -> <device-port>
#   7. prove the handshake with `frida-ps -H`
#   8. print the ready-to-use `-H 127.0.0.1:<local-port>` endpoint
#
# Usage:
#   tools/frida-connect.sh -s SERIAL [-b DEVICE_BIN] [-p LOCAL_PORT] [-r DEVICE_PORT]
#
#   -s SERIAL       adb serial / endpoint (REQUIRED, e.g. 127.0.0.1:5619)
#   -b DEVICE_BIN   server path on device   (default: /data/local/tmp/art-runtime-srv)
#   -p LOCAL_PORT   host-side forward port  (default: 27042)
#   -r DEVICE_PORT  port the server listens on (default: 27042)
#   -h              show this help
#
# Env:
#   ADB             adb binary to use (default: adb on PATH)
#   FRIDA           frida client binary for the version check (default: frida on PATH)
set -euo pipefail

SERIAL=""
BIN="/data/local/tmp/art-runtime-srv"
LOCAL_PORT="27042"
DEVICE_PORT="27042"

while getopts "s:b:p:r:h" opt; do
  case "$opt" in
    s) SERIAL="$OPTARG" ;;
    b) BIN="$OPTARG" ;;
    p) LOCAL_PORT="$OPTARG" ;;
    r) DEVICE_PORT="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^#\{0,1\} \{0,1\}//'; exit 0 ;;
    *) exit 2 ;;
  esac
done

ADB_BIN="${ADB:-adb}"
FRIDA_BIN="${FRIDA:-frida}"
NAME="$(basename "$BIN")"

die() { echo "ERROR: $*" >&2; exit 1; }
[ -n "$SERIAL" ] || die "missing -s SERIAL (adb endpoint, e.g. 127.0.0.1:5619). Open the JW tunnel first via the jw-adb skill / phone_open_adb."

ADB=("$ADB_BIN" -s "$SERIAL")

# --- 1. device reachable + rooted -------------------------------------------
state="$("$ADB_BIN" -s "$SERIAL" get-state 2>/dev/null || true)"
[ "$state" = "device" ] || die "adb device '$SERIAL' is '${state:-unreachable}'. Re-open the tunnel (phone_open_adb) — JW tunnels expire after ~1h."
"${ADB[@]}" shell 'su -c id' 2>/dev/null | grep -q 'uid=0' \
  || die "no root on '$SERIAL' (su failed). These test devices are expected to be rooted."

# --- 2. server version (straight off the renamed binary) --------------------
"${ADB[@]}" shell "su -c 'test -x $BIN'" 2>/dev/null || true
SERVER_VER="$("${ADB[@]}" shell "su -c '$BIN --version'" 2>/dev/null | tr -d '\r' | head -1)"
[ -n "$SERVER_VER" ] || die "could not read server version from $BIN on $SERIAL (binary missing, or not the Morphida server). Deploy it first."

# --- 3. local client version -------------------------------------------------
CLIENT_VER="$("$FRIDA_BIN" --version 2>/dev/null | tr -d '\r' | head -1)"
[ -n "$CLIENT_VER" ] || die "could not read local '$FRIDA_BIN --version' — is the frida client installed?"

echo "server ($NAME @ $SERIAL): $SERVER_VER"
echo "client ($FRIDA_BIN):       $CLIENT_VER"

# --- 4. THE assertion --------------------------------------------------------
if [ "$SERVER_VER" != "$CLIENT_VER" ]; then
  cat >&2 <<EOF

VERSION MISMATCH — frida will not handshake across versions.
  server: $SERVER_VER
  client: $CLIENT_VER

Fix one side so they match, then re-run:
  # match client to server:
  python -m pip install --upgrade "frida==$SERVER_VER"
  # ...or redeploy the matching server build to the device.
EOF
  exit 3
fi
echo "version OK ($SERVER_VER == $CLIENT_VER)"

# --- 5. ensure daemon running ------------------------------------------------
if "${ADB[@]}" shell "su -c 'pidof $NAME'" 2>/dev/null | grep -qE '[0-9]'; then
  echo "daemon already running."
else
  echo "daemon not running — starting on 0.0.0.0:$DEVICE_PORT ..."
  "${ADB[@]}" shell "su -c 'setenforce 0 2>/dev/null; nohup $BIN -l 0.0.0.0:$DEVICE_PORT >/data/local/tmp/${NAME}.log 2>&1 &'" >/dev/null 2>&1 || true
  ok=""
  for _ in 1 2 3 4 5; do
    if "${ADB[@]}" shell "su -c 'pidof $NAME'" 2>/dev/null | grep -qE '[0-9]'; then ok=1; break; fi
    sleep 1
  done
  [ -n "$ok" ] || die "daemon failed to start. Check: ${ADB[*]} shell \"su -c 'cat /data/local/tmp/${NAME}.log'\""
  echo "daemon started."
fi

# --- 6. forward --------------------------------------------------------------
"${ADB[@]}" forward "tcp:$LOCAL_PORT" "tcp:$DEVICE_PORT" >/dev/null \
  || die "adb forward failed (local port $LOCAL_PORT may be in use — try -p <other>)."

# --- 7. prove the handshake --------------------------------------------------
if ! "$FRIDA_BIN-ps" -H "127.0.0.1:$LOCAL_PORT" >/dev/null 2>&1; then
  die "forwarded but frida-ps handshake failed on 127.0.0.1:$LOCAL_PORT. Check the daemon log on device."
fi

# --- 8. deliver --------------------------------------------------------------
cat <<EOF

READY — frida $SERVER_VER on $SERIAL
  endpoint:  127.0.0.1:$LOCAL_PORT
  list:      frida-ps -H 127.0.0.1:$LOCAL_PORT
  spawn:     frida -H 127.0.0.1:$LOCAL_PORT -f <pkg> -l hook.js
  attach:    frida -H 127.0.0.1:$LOCAL_PORT -n <name> -l hook.js
EOF
