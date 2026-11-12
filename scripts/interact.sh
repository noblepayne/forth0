#!/usr/bin/env bash
# interact.sh — YOUR turn. Boots the forth.ko guest and drops you at a
# root shell with the REPL node live and a fileless victim pre-staged.
# Type the sentences yourself; the kernel answers. `poweroff -f` to leave.
#
# VM only: no host insmod, no sudo, no firmware. Ctrl-C kills the guest
# (trap below). Guest -m 1536.
set -u

KO=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/forth/forth.ko
BUSYBOX=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/vm/stage/bin/busybox
BZIMAGE=/nix/store/067gji6lk8xx8rmlkykvcq07nql619wp-linux-zen-7.2.3/bzImage
GCROOT=${RFORTH_WORK:-/dev/shm/rustforth-kmod}/gcroot

fail() { echo "interact.sh: MISSING: $1" >&2; exit 2; }
command -v qemu-system-x86_64 >/dev/null 2>&1 || fail "qemu-system-x86_64 not on PATH"
[ -e /dev/kvm ] || fail "/dev/kvm absent (KVM unavailable)"
[ -f "$KO" ] || fail "forth.ko $KO absent"
[ -x "$BUSYBOX" ] || fail "static busybox $BUSYBOX absent"
[ -f "$BZIMAGE" ] || fail "guest kernel $BZIMAGE absent"
command -v cpio >/dev/null 2>&1 || fail "cpio not on PATH"

WORK=$(mktemp -d /dev/shm/interact.XXXXXX)
CPIO=$WORK/initramfs.cpio
trap 'pkill -9 -f "qemu-system-x86_64.*$CPIO" 2>/dev/null; rm -rf "$WORK"' EXIT

mkdir -p "$WORK/stage/bin" "$WORK/stage/dev" "$WORK/stage/proc" "$WORK/stage/sys" "$WORK/stage/tmp"
cp -a "$BUSYBOX" "$WORK/stage/bin/busybox"
for a in sh insmod rmmod mount cat echo stat dmesg poweroff reboot sleep grep nc ps ls mkdir rm cp head tail; do
  ln -s busybox "$WORK/stage/bin/$a"
done
cp "$KO" "$WORK/stage/forth.ko"
cat > "$WORK/stage/init" <<'GUEST_EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
insmod /forth.ko && echo "forth: loaded. repl at /sys/kernel/debug/forth/repl"
# Stage the fileless victim (deleted exe + TCP socket), same as OTP-FL proof.
cp /bin/busybox /tmp/busybox
/tmp/busybox nc -l -p 12345 &
sleep 1
rm -f /tmp/busybox
echo "victim staged: deleted-exe process holding a TCP socket."
echo "--- try: echo \"tasks fileless\" > R; cat R  (R=/sys/kernel/debug/forth/repl)"
exec /bin/sh
GUEST_EOF
chmod +x "$WORK/stage/init"
(cd "$WORK/stage" && find . | cpio -o --format=newc > "$CPIO" 2>/dev/null) \
  || { echo "interact.sh: initramfs assembly failed" >&2; exit 2; }

R=/sys/kernel/debug/forth/repl
cat <<CHEAT
=== forth.ko interactive guest ===
repl node: $R   (usage: echo "<sentence>" > \$R; cat \$R)
  toy:      echo "2 3 + ." > \$R; cat \$R
  useful:   echo "tasks fileless" > \$R; cat \$R        # victim pre-staged
  reveal:   echo "unix" > \$R; cat \$R
  cursed:   echo "do_exit" > \$R; cat \$R
  error:    echo "frobnicate" > \$R; cat \$R
  state:    echo "mem" > \$R; cat \$R
leave: poweroff -f   (or Ctrl-C here kills the guest)
=== booting (KVM, 1536M) ===
CHEAT

qemu-system-x86_64 -enable-kvm -m 1536 \
  -kernel "$BZIMAGE" -initrd "$CPIO" \
  -display none -serial stdio -monitor none -no-reboot \
  -append "console=ttyS0 panic=-1"
