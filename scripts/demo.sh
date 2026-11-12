#!/usr/bin/env bash
# demo.sh — one-command reproduction of the forth.ko guest proof (OTP-V).
#
# From a cold start: checks prerequisites, assembles an initramfs from
# ${RFORTH_WORK:-/dev/shm/rustforth-kmod}/forth/forth.ko + the proven static busybox,
# boots a KVM guest, evals a fixed sentence list against
# /sys/kernel/debug/forth/repl, prints the SENT/reply transcript to
# stdout, and exits 0 iff every sentence got its `ok` sentinel.
#
# Read-only-safe: no insmod/rmmod on the host, no sudo, no firmware writes.
# All scratch lives under /dev/shm. Guest -m 1536; a guest-side watchdog
# plus an outer `timeout` mean this can never hang the evening.
set -u

KO=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/forth/forth.ko
BUSYBOX=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/vm/stage/bin/busybox
BZIMAGE=/nix/store/067gji6lk8xx8rmlkykvcq07nql619wp-linux-zen-7.2.3/bzImage
GCROOT=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/gcroot
KBUILD=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/kbuild
# Fixed sentence list — the four OTP-V proof sentences, beat 2 FIXED
# (Wes ruling 2026-11-02: live line is `unix`, not `unix orphans peers`;
# the emptiness result stays in the collection as a possible later beat).
SENTS=( "mem" "do_exit" "2 3 + ." "unix" )
MEM=1536
TIMEOUT_S=240

fail() { echo "demo.sh: MISSING: $1" >&2; exit 2; }

# ---- (1) fail-fast prerequisite checks (each names its piece) ----
command -v qemu-system-x86_64 >/dev/null 2>&1 || fail "qemu-system-x86_64 not on PATH"
[ -e /dev/kvm ] || fail "/dev/kvm absent (KVM unavailable)"
[ -L "$GCROOT" ] || fail "gcroot symlink $GCROOT absent"
[ -d "$GCROOT" ] || fail "gcroot target $(readlink "$GCROOT") missing (nix store GC'd?)"
[ -f "$KBUILD/Makefile" ] || fail "kbuild tree $KBUILD missing/incomplete"
[ -f "$KO" ] || fail "forth.ko $KO absent (rebuild via build-forth-kbuild.sh)"
[ -x "$BUSYBOX" ] || fail "static busybox $BUSYBOX absent"
[ -f "$BZIMAGE" ] || fail "guest kernel $BZIMAGE absent"
command -v cpio >/dev/null 2>&1 || fail "cpio not on PATH"

WORK=$(mktemp -d /dev/shm/demo.XXXXXX)
CPIO=$WORK/initramfs.cpio
SERIAL=$WORK/serial.log
# Kill qemu on ALL paths (success, failure, Ctrl-C); then drop scratch.
trap 'pkill -9 -f "qemu-system-x86_64.*$CPIO" 2>/dev/null; rm -rf "$WORK"' EXIT

# ---- (2) assemble initramfs (vm/stage layout: bin/ + init + forth.ko) ----
mkdir -p "$WORK/stage/bin" "$WORK/stage/dev" "$WORK/stage/proc" "$WORK/stage/sys"
cp -a "$BUSYBOX" "$WORK/stage/bin/busybox"
for a in sh insmod rmmod mount cat echo stat dmesg poweroff reboot sleep grep; do
  ln -s busybox "$WORK/stage/bin/$a"
done
cp "$KO" "$WORK/stage/forth.ko"
cat > "$WORK/stage/init" <<'GUEST_EOF'
#!/bin/sh
# demo guest /init: insmod forth.ko, eval fixed sentences, power off.
# 120s watchdog: force reboot so qemu can never hang.
(sleep 120; echo WATCHDOG-REBOOT; reboot -f) &
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
insmod /forth.ko
echo "forth insmod exit: $?"
stat /sys/kernel/debug/forth/repl
run() {
  echo "--- SENT >>> $1"
  echo "$1" > /sys/kernel/debug/forth/repl
  echo "write exit: $?"
  cat /sys/kernel/debug/forth/repl
  echo "--- SENT <<< done"
}
run "mem"
run "do_exit"
run "2 3 + ."
run "unix"
echo "--- WARN/OOPS check ---"
dmesg | grep -iE 'warn|oops|bug:|panic' | head -20
echo "=== demo done, poweroff ==="
poweroff -f
sleep 5
reboot -f
GUEST_EOF
chmod +x "$WORK/stage/init"
(cd "$WORK/stage" && find . | cpio -o --format=newc > "$CPIO" 2>/dev/null) \
  || { echo "demo.sh: initramfs assembly failed" >&2; exit 2; }

# ---- (3) boot the guest ----
timeout "$TIMEOUT_S" qemu-system-x86_64 \
  -enable-kvm -m "$MEM" \
  -kernel "$BZIMAGE" -initrd "$CPIO" \
  -nographic -no-reboot -append "console=ttyS0 panic=-1" \
  >"$SERIAL" 2>&1
rc=$?
[ $rc -eq 124 ] && { echo "demo.sh: guest timed out after ${TIMEOUT_S}s" >&2; exit 1; }
[ $rc -ne 0 ] && { echo "demo.sh: qemu exited $rc (see transcript below)" >&2; }

# ---- (4) print transcript, verify one `ok` per sentence ----
N=${#SENTS[@]}
strip_cr() { tr -d '\r' < "$SERIAL"; }
strip_cr | awk '/--- SENT >>>/{p=1} p{print} /--- SENT <<< done/{if(++n=='"$N"') exit}'
region=$(strip_cr | awk '/--- SENT >>>/{p=1} p{print} /--- SENT <<< done/{if(++n=='"$N"') exit}')
sent=$(printf '%s\n' "$region" | grep -c -- '--- SENT >>>' || true)
done_n=$(printf '%s\n' "$region" | grep -c -- '--- SENT <<< done' || true)
oks=$(printf '%s\n' "$region" | grep -c -- '^ok$' || true)
errs=$(printf '%s\n' "$region" | grep -c -- '^err' || true)
if [ "$sent" -eq "$N" ] && [ "$done_n" -eq "$N" ] && [ "$oks" -eq "$N" ] && [ "$errs" -eq 0 ]; then
  echo "DEMO: $N/$N sentences got 'ok' — green"
  exit 0
else
  echo "demo.sh: RED (sent=$sent done=$done_n ok=$oks err=$errs, want $N/$N/$N/0)" >&2
  exit 1
fi
