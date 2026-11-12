#!/usr/bin/env bash
# record.sh — OTP-R slide-capture kit: turn deterministic VM takes into
# slide-ready artifacts, one directory per beat under captures/.
#
# Modeled on demo.sh's structure: (1) fail-fast prereqs, (2) per-beat
# initramfs assembly, (3) qemu guest boot under asciinema, (4) transcript
# extraction + verification. Deterministic: fixed sentence lists, -m 1536,
# guest watchdog + outer timeout, qemu killed on ALL paths.
#
# Usage: ./record.sh [beat ...]   (default: all 8 beats)
#   Beats: toy reveal useful cursed error transport panic uname
#
# Per beat dir captures/<beat>/: transcript.txt (verbatim SENT/reply),
# take.cast (asciinema of the guest serial session), STILL.txt (3-8 lines
# for the slide). Plus CAPTURES.md index (written by hand after curation).
#
# Read-only-safe on the host: no insmod/rmmod, no sudo, no network, no
# commits. Scratch lives under vmr/ (VM runs). Guest -m 1536.
set -u

BASE=${RFORTH_WORK:-/dev/shm/rustforth-kmod}
KO=$BASE/forth/forth.ko
STORE_KO=$BASE/store-scratch/forth.ko  # uname beat only (OTP-TAKE pattern)
BUSYBOX=$BASE/vm/stage/bin/busybox
BZIMAGE=/nix/store/067gji6lk8xx8rmlkykvcq07nql619wp-linux-zen-7.2.3/bzImage
GCROOT=$BASE/gcroot
KBUILD=$BASE/kbuild
KEEPER=/tmp/opencode/keeper/keeper
GLIBC=/nix/store/n51dhmdbik1kfrsm62j5knavmigwrl1a-glibc-2.42-84
VMR=$BASE/vmr
CAP=$BASE/captures
ASCINEMA=/dev/shm/asciinema-probe/bin/asciinema
MEM=1536
TIMEOUT_S=240
PANIC_CAP=150

ALL_BEATS=(toy reveal useful cursed error transport panic uname)
BEATS=("${@:-${ALL_BEATS[@]}}")

PASS=0; FAIL=0; RESULTS=()

fail() { echo "record.sh: MISSING: $1" >&2; exit 2; }
beat_ok()  { echo "BEAT $1: GREEN — $2"; PASS=$((PASS+1)); RESULTS+=("$1 GREEN"); }
beat_bad() { echo "BEAT $1: RED — $2" >&2; FAIL=$((FAIL+1)); RESULTS+=("$1 RED"); }

# ---- (1) fail-fast prerequisite checks (each names its piece) ----
command -v qemu-system-x86_64 >/dev/null 2>&1 || fail "qemu-system-x86_64 not on PATH"
[ -e /dev/kvm ] || fail "/dev/kvm absent (KVM unavailable)"
[ -L "$GCROOT" ] || fail "gcroot symlink $GCROOT absent"
[ -d "$GCROOT" ] || fail "gcroot target $(readlink "$GCROOT") missing (nix store GC'd?)"
[ -f "$KBUILD/Makefile" ] || fail "kbuild tree $KBUILD missing/incomplete"
[ -f "$KO" ] || fail "forth.ko $KO absent (use as-is; do NOT rebuild)"
[ -f "$STORE_KO" ] || fail "store-scratch forth.ko $STORE_KO absent (uname beat needs it as-is)"
[ -x "$BUSYBOX" ] || fail "static busybox $BUSYBOX absent"
[ -f "$BZIMAGE" ] || fail "guest kernel $BZIMAGE absent"
command -v cpio >/dev/null 2>&1 || fail "cpio not on PATH"
if [ -x "$ASCINEMA" ]; then HAVE_CAST=1; else HAVE_CAST=0; echo "record.sh: NOTE: asciinema absent at $ASCINEMA — casts skipped, transcripts still captured" >&2; fi
# keeper fixture (reveal beat): primary recipe path, fallback to peer stage copy
if [ -x "$KEEPER" ]; then :;
elif [ -x "$BASE/peer/stage/keeper" ]; then KEEPER=$BASE/peer/stage/keeper;
else fail "keeper binary absent ($KEEPER and peer/stage/keeper both missing)"
fi
[ -f "$GLIBC/lib/libc.so.6" ] || fail "glibc libc.so.6 absent ($GLIBC)"
[ -f "$GLIBC/lib/ld-linux-x86-64.so.2" ] || fail "glibc loader absent ($GLIBC)"
export TERM=${TERM:-xterm}

mkdir -p "$VMR" "$CAP"
# Global safety net: no stray qemu survives this script.
trap 'pkill -9 -f "qemu-system-x86_64.*$VMR" 2>/dev/null; true' EXIT

APPLETS="sh insmod rmmod mount cat echo stat dmesg poweroff reboot sleep grep uname head mkdir ls ps rm cp ln"

stage_common() { # $1 = WORK — shared initramfs skeleton
  local WORK=$1
  mkdir -p "$WORK/stage/bin" "$WORK/stage/dev" "$WORK/stage/proc" "$WORK/stage/sys"
  cp -a "$BUSYBOX" "$WORK/stage/bin/busybox"
  # shellcheck disable=SC2086
  for a in $APPLETS; do ln -sf busybox "$WORK/stage/bin/$a"; done
  cp "$KO" "$WORK/stage/forth.ko"
}

stage_keeper() { # $1 = WORK — reveal-beat keeper fixture (OTP-FIX-batch recipe)
  local WORK=$1
  cp "$KEEPER" "$WORK/stage/keeper"; chmod +x "$WORK/stage/keeper"
  mkdir -p "$WORK/stage/${GLIBC#/}/lib" "$WORK/stage/lib"
  cp "$GLIBC/lib/ld-linux-x86-64.so.2" "$WORK/stage/${GLIBC#/}/lib/"
  cp "$GLIBC/lib/libc.so.6" "$WORK/stage/lib/"
}

GUEST_HEAD='(sleep 120; echo WATCHDOG-REBOOT; reboot -f) &
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
insmod /forth.ko
echo "forth insmod exit: $?"
'

GUEST_RUN_FN='run() {
  echo "--- SENT >>> $1"
  echo "$1" > /sys/kernel/debug/forth/repl
  echo "write exit: $?"
  cat /sys/kernel/debug/forth/repl
  echo "--- SENT <<< done"
}
'

guest_init_for() { # $1 = beat — prints the guest /init body
  case $1 in
    toy) printf '%s\n%s\nrun "2 3 + ."\n%s\n' "$GUEST_HEAD" "$GUEST_RUN_FN" \
      'echo "=== toy done, poweroff ==="; poweroff -f; sleep 5; reboot -f';;
    reveal) printf '%s\n%s\n%s\nrun "unix"\n%s\n' "$GUEST_HEAD" \
      'LD_LIBRARY_PATH=/lib /keeper &
sleep 2' "$GUEST_RUN_FN" \
      'echo "=== reveal done, poweroff ==="; poweroff -f; sleep 5; reboot -f';;
    useful) printf '%s\n%s\n%s\nrun "tasks fileless"\n%s\n' "$GUEST_HEAD" \
      'mkdir -p /tmp
cp /bin/busybox /tmp/busybox
/tmp/busybox nc -l -p 12345 &
sleep 1
rm -f /tmp/busybox' "$GUEST_RUN_FN" \
      'echo "=== useful done, poweroff ==="; poweroff -f; sleep 5; reboot -f';;
    cursed) printf '%s\n%s\nrun "do_exit"\n%s\n' "$GUEST_HEAD" "$GUEST_RUN_FN" \
      'echo "=== cursed done, poweroff ==="; poweroff -f; sleep 5; reboot -f';;
    error) printf '%s\n%s\nrun "frobnicate"\n%s\n' "$GUEST_HEAD" "$GUEST_RUN_FN" \
      'echo "=== error done, poweroff ==="; poweroff -f; sleep 5; reboot -f';;
    transport) printf '%s\nstat /sys/kernel/debug/forth/repl\necho "=== transport done, poweroff ==="; poweroff -f; sleep 5; reboot -f\n' \
      "$GUEST_HEAD";;
    panic) printf '%s\n%s\nrun "arm"\nrun "armed?"\necho "=== CLOSING-WRITE: armed do_exit now ==="\necho "do_exit" > /sys/kernel/debug/forth/repl\necho "write exit: $?"\necho "STILL-ALIVE (no panic — armed path failed)"\nsleep 5\nreboot -f\n' \
      '(sleep 90; echo WATCHDOG-NO-PANIC; reboot -f) &
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
insmod /forth.ko
echo "forth insmod exit: $?"' "$GUEST_RUN_FN";;
    uname) printf '%s\n%s\necho "=== pre-lie uname ==="\nuname -r\nrun "mem"\nrun "utsrel"\nrun "utsrel 7312206642831044151 !"\nrun "utsrel 8 + 5211881169207767406 !"\nrun "0 65 c!"\necho "=== post-lie uname -r ==="\nuname -r\necho "=== post-lie uname -a ==="\nuname -a\necho "=== /proc/version ==="\ncat /proc/version\nrun "frobnicate"\necho "=== take-uname done, poweroff ==="; poweroff -f; sleep 5; reboot -f\n' \
      "$GUEST_HEAD" "$GUEST_RUN_FN";;
  esac
}

# ---- per-beat runner ----
run_beat() { # $1 = beat
  local beat=$1
  local WORK BEATDIR CPIO SERIAL RAW
  WORK=$(mktemp -d "$VMR/$beat.XXXXXX")
  BEATDIR=$CAP/$beat
  CPIO=$WORK/initramfs.cpio
  SERIAL=$WORK/serial.log
  RAW=$WORK/raw.log
  # Kill THIS beat's qemu on all paths; keep scratch for forensics on RED.
  trap 'pkill -9 -f "qemu-system-x86_64.*$CPIO" 2>/dev/null; true' RETURN

  mkdir -p "$BEATDIR"
  stage_common "$WORK"
  [ "$beat" = "reveal" ] && stage_keeper "$WORK"
  [ "$beat" = "uname" ] && cp "$STORE_KO" "$WORK/stage/forth.ko"  # OTP-TAKE: scratch .ko has utsrel/!/c!
  { echo '#!/bin/sh'; guest_init_for "$beat"; } > "$WORK/stage/init"
  chmod +x "$WORK/stage/init"
  (cd "$WORK/stage" && find . | cpio -o --format=newc > "$CPIO" 2>/dev/null) \
    || { beat_bad "$beat" "initramfs assembly failed"; return; }

  if [ "$beat" = "panic" ]; then
    cat > "$WORK/run.sh" <<EOF
#!/usr/bin/env bash
T_START=\$(date +%s)
timeout $PANIC_CAP qemu-system-x86_64 -enable-kvm -m $MEM -kernel "$BZIMAGE" -initrd "$CPIO" -nographic -no-reboot -append "console=ttyS0 " < /dev/null >"$SERIAL" 2>&1 &
QPID=\$!
tail -n +1 -F "$SERIAL" 2>/dev/null &
TAILPID=\$!
PANIC_T=""
while kill -0 \$QPID 2>/dev/null; do
  sleep 1; NOW=\$(date +%s)
  if [ -z "\$PANIC_T" ] && grep -q 'Attempted to kill init' "$SERIAL" 2>/dev/null; then PANIC_T=\$NOW; fi
  if [ -n "\$PANIC_T" ]; then
    MTIME=\$(stat -c %Y "$SERIAL")
    if [ \$((NOW - MTIME)) -ge 10 ]; then break; fi
    if [ \$((NOW - PANIC_T)) -ge 40 ]; then break; fi
  fi
  if [ \$((NOW - T_START)) -ge $((PANIC_CAP - 5)) ]; then break; fi
done
kill -9 \$QPID 2>/dev/null; wait \$QPID 2>/dev/null
kill \$TAILPID 2>/dev/null
tr -d '\r' < "$SERIAL" > "$RAW"; mv "$RAW" "$SERIAL"
echo "run.sh: panic beat qemu reaped"
EOF
  else
    cat > "$WORK/run.sh" <<EOF
#!/usr/bin/env bash
# tee: the pty (asciinema cast) sees the live session AND raw.log keeps it.
timeout $TIMEOUT_S qemu-system-x86_64 -enable-kvm -m $MEM -kernel "$BZIMAGE" -initrd "$CPIO" -nographic -no-reboot -append "console=ttyS0 panic=-1" < /dev/null 2>&1 | tee "$RAW"
echo "run.sh: qemu exit \${PIPESTATUS[0]} (124=timeout)"
tr -d '\r' < "$RAW" > "$SERIAL"
EOF
  fi
  chmod +x "$WORK/run.sh"

  if [ "$HAVE_CAST" -eq 1 ]; then
    "$ASCINEMA" rec --headless --overwrite --idle-time-limit 2.0 \
      --title "rustforth: $beat" --command "bash $WORK/run.sh" \
      "$BEATDIR/take.cast" >/dev/null 2>&1 \
      || echo "record.sh: NOTE: asciinema rec failed for $beat — transcript still captured" >&2
  fi
  # If asciinema is absent (or rec failed), run the take directly.
  if [ ! -s "$SERIAL" ]; then
    echo "record.sh: NOTE: $beat has no serial from cast run — retrying directly" >&2
    bash "$WORK/run.sh" >/dev/null 2>&1
  fi
  cp -a "$SERIAL" "$BEATDIR/serial.log"

  # ---- (4) transcript extraction + verification + STILL curation ----
  case $beat in
    toy|reveal|useful|cursed)
      case $beat in toy) SENTENCE='2 3 + .';; reveal) SENTENCE='unix';; useful) SENTENCE='tasks fileless';; cursed) SENTENCE='do_exit';; esac
      awk "/--- SENT >>>/{p=1} p{print} /--- SENT <<< done/{exit}" "$SERIAL" > "$BEATDIR/transcript.txt"
      { grep -- "--- SENT >>> $SENTENCE" "$BEATDIR/transcript.txt"
        grep -m1 'write exit' "$BEATDIR/transcript.txt"
        grep -E '^(text|int|ints|task|err|unix) ' "$BEATDIR/transcript.txt" | head -5
        grep -m1 '^ok$' "$BEATDIR/transcript.txt"; } > "$BEATDIR/STILL.txt"
      if grep -q '^ok$' "$BEATDIR/transcript.txt"; then beat_ok "$beat" "$SENTENCE → ok (see $BEATDIR/)";
      else beat_bad "$beat" "no ok in transcript (see $BEATDIR/serial.log)"; fi;;
    error)
      awk "/--- SENT >>>/{p=1} p{print} /--- SENT <<< done/{exit}" "$SERIAL" > "$BEATDIR/transcript.txt"
      { grep -- '--- SENT >>> frobnicate' "$BEATDIR/transcript.txt"
        grep -m1 'write exit' "$BEATDIR/transcript.txt"
        grep -m1 '^err undefined word: frobnicate$' "$BEATDIR/transcript.txt"; } > "$BEATDIR/STILL.txt"
      if grep -q '^err undefined word: frobnicate$' "$BEATDIR/transcript.txt"; then beat_ok "$beat" "frobnicate → clean err (see $BEATDIR/)";
      else beat_bad "$beat" "no clean err in transcript (see $BEATDIR/serial.log)"; fi;;
    transport)
      awk '/forth insmod exit/{p=1} p{print} /transport done/{exit}' "$SERIAL" > "$BEATDIR/transcript.txt"
      { grep -m1 'forth insmod exit' "$BEATDIR/transcript.txt"
        grep -m1 'File: /sys/kernel/debug/forth/repl' "$BEATDIR/transcript.txt"
        grep -m1 'Size:' "$BEATDIR/transcript.txt"; } > "$BEATDIR/STILL.txt"
      if grep -q 'forth insmod exit: 0' "$BEATDIR/transcript.txt" && grep -q 'forth/repl' "$BEATDIR/transcript.txt"; then
        beat_ok "$beat" "insmod 0 + repl node present (see $BEATDIR/)";
      else beat_bad "$beat" "insmod/stat region wrong (see $BEATDIR/serial.log)"; fi;;
    panic)
      awk '/--- SENT >>> arm/{p=1} p{print} /end Kernel panic/{exit}' "$SERIAL" > "$BEATDIR/transcript.txt"
      { grep -- '--- SENT >>> armed?' "$BEATDIR/transcript.txt"
        grep -m1 'text cursed ARMED' "$BEATDIR/transcript.txt"
        grep -m1 'CLOSING-WRITE' "$SERIAL"
        grep -m1 'Kernel panic - not syncing' "$BEATDIR/transcript.txt" | sed 's/^\[[^]]*\] //'
        grep -m1 'w_do_exit' "$BEATDIR/transcript.txt" | sed 's/^\[[^]]*\] //'
        grep -m1 'end Kernel panic' "$BEATDIR/transcript.txt" | sed 's/^\[[^]]*\] //'; } > "$BEATDIR/STILL.txt"
      if grep -q 'Attempted to kill init' "$BEATDIR/transcript.txt" && ! grep -q 'STILL-ALIVE' "$BEATDIR/transcript.txt"; then
        beat_ok "$beat" "guest froze on the splat (see $BEATDIR/)";
      else beat_bad "$beat" "no panic / guest survived (see $BEATDIR/serial.log)"; fi;;
    uname)
      awk '/=== pre-lie uname ===/{p=1} p{print} /--- SENT <<< done/{c++} c==6{exit}' "$SERIAL" > "$BEATDIR/transcript.txt"
      { grep -- '--- SENT >>> utsrel 7312206642831044151 !$' "$BEATDIR/transcript.txt"
        grep -A2 -- '--- SENT >>> utsrel 7312206642831044151 !$' "$BEATDIR/transcript.txt" | grep -m1 '^ok$'
        awk '/=== pre-lie uname ===/{getline; print "pre:  "$0}' "$SERIAL"
        awk '/=== post-lie uname -r ===/{getline; print "post: "$0}' "$SERIAL"; } > "$BEATDIR/STILL.txt"
      if awk '/=== post-lie uname -r ===/{getline; exit ($0 ~ /FORTH/ ? 0 : 1)}' "$SERIAL"; then
        beat_ok "$beat" "uname -r carries -FORTH (see $BEATDIR/)";
      else beat_bad "$beat" "post-lie uname lacks -FORTH (see $BEATDIR/serial.log)"; fi;;
  esac
  pkill -9 -f "qemu-system-x86_64.*$CPIO" 2>/dev/null; true
}

T0=$(date +%s)
for b in "${BEATS[@]}"; do
  case " ${ALL_BEATS[*]} " in *" $b "*) run_beat "$b";; *) echo "record.sh: unknown beat '$b'" >&2;; esac
done
T1=$(date +%s)
echo "record.sh: beats GREEN=$PASS RED=$FAIL wall=$((T1-T0))s — ${RESULTS[*]}"
[ "$FAIL" -eq 0 ]
