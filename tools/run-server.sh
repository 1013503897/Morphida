#!/usr/bin/env bash
# Hardened launch helper for a Morphida frida-server on an adb device.
#
# Defeats the two cheapest network-level detections — the fixed 27042 port and
# the bare D-Bus handshake — by listening on a random port behind an auth token,
# then exposing it locally via `adb forward`.
#
# Usage:
#   tools/run-server.sh [-s SERIAL] [-b DEVICE_BIN_PATH] [-p LOCAL_PORT]
#
#   -s SERIAL   adb device serial (omit if only one device)
#   -b PATH     server path on device (default: /data/local/tmp/frida-server)
#   -p PORT     host-side forwarded port (default: same as the random device port)
#
# Prints the matching `frida -H 127.0.0.1:<port> --token <token>` command.
# Note: with a custom port + token, `frida -U` no longer works out of the box —
# connect with `-H` + `--token` as printed below.
set -euo pipefail

SERIAL=""
BIN="/data/local/tmp/frida-server"
LOCAL_PORT=""

while getopts "s:b:p:h" opt; do
  case "$opt" in
    s) SERIAL="$OPTARG" ;;
    b) BIN="$OPTARG" ;;
    p) LOCAL_PORT="$OPTARG" ;;
    h) grep '^#' "$0" | sed 's/^#\{0,1\} \{0,1\}//'; exit 0 ;;
    *) exit 2 ;;
  esac
done

ADB=(adb)
[ -n "$SERIAL" ] && ADB=(adb -s "$SERIAL")

NAME="$(basename "$BIN")"
PORT="$(( 30000 + RANDOM % 30000 ))"
TOKEN="$("${ADB[@]}" shell 'cat /proc/sys/kernel/random/uuid' | tr -d '\r\n-')"
[ -n "$LOCAL_PORT" ] || LOCAL_PORT="$PORT"

echo "[run-server] device : ${SERIAL:-<default>}"
echo "[run-server] binary : $BIN"
echo "[run-server] listen : 127.0.0.1:$PORT  (token ${TOKEN:0:8}...)"

# Kill prior instances of THIS binary by matching /proc/<pid>/cmdline prefix.
# The killer shell's own cmdline starts with "su", never with "$BIN", so it
# can't match (and kill) itself — unlike `pkill -f frida-server`.
"${ADB[@]}" shell "su -c 'for d in /proc/[0-9]*; do c=\$(tr \"\\0\" \" \" < \$d/cmdline 2>/dev/null); case \"\$c\" in \"$BIN \"*) kill \${d#/proc/} 2>/dev/null;; esac; done'" || true

# Launch detached on a random loopback port behind the auth token.
"${ADB[@]}" shell "su -c 'setsid $BIN -l 127.0.0.1:$PORT --token $TOKEN >/data/local/tmp/$NAME.log 2>&1 </dev/null &'"

# Wait for the listener, then forward host -> device.
"${ADB[@]}" shell "su -c 'for i in 1 2 3 4 5; do netstat -tln 2>/dev/null | grep -q 127.0.0.1:$PORT && break; sleep 1; done'"
"${ADB[@]}" forward "tcp:$LOCAL_PORT" "tcp:$PORT" >/dev/null

echo
echo "[run-server] connect with:"
echo "    frida-ps -H 127.0.0.1:$LOCAL_PORT --token $TOKEN"
echo "    frida   -H 127.0.0.1:$LOCAL_PORT --token $TOKEN -f <package>"
