// SPDX-License-Identifier: GPL-2.0

//! forth: in-kernel Forth, Step 2 (demo words + hardening).
//!
//! Transport: raw `file_operations` (`read`/`write`) on a debugfs file
//! `/sys/kernel/debug/forth/repl`, created with mode 0600 explicitly via
//! `debugfs_create_file_full` (the Step-1 safe callback wrapper is gone: its
//! monomorphized write adapter was the SOLE source of
//! `panic_const_*_overflow` refs in the Step-1 object -- see the build
//! receipt -- and it chose the file mode internally). One write carries one
//! Forth line (max 4096 bytes incl. newline, longer yields `-E2BIG` with no
//! eval); the line is evaluated synchronously inside the write path and the
//! typed response is stored; the following read(s) emit it with `*ppos`
//! tracking (first read returns up to the user length, later reads EOF).
//!
//! Concurrency: the backing `Mutex<Inner>` IS the single-writer guard. A
//! write uses `try_lock` (fails with `-EBUSY` while another eval runs). A
//! read uses blocking `lock()`, so it sleeps until an in-flight eval
//! completes and then emits the full response, never a partial one.
//!
//! Wire rendering (spec `line-protocol-v0.1.md`): value lines use the fixed
//! tags `int` / `ints` / `unix` / `task` / `text`, terminated by the `ok`
//! sentinel; word-level failure stores a single `err <message>` line instead
//! (the write itself still succeeds). On any failure the partial output built
//! so far is discarded. `read` before any write returns EOF (zero bytes).
//!
//! Value model: the data stack holds `Int` scalars plus collection
//! descriptors `{kind, slot, n}` that view two static scratch buffers per
//! kind (`UNIX_BUF`, `TASK_BUF`, `INT_BUF`, each `[2]`). Producing a
//! collection picks the slot no live stack value references; `dup` on a
//! collection copies into the free slot; with both slots live the word fails
//! cleanly (`err no buffer`) instead of aliasing. Buffers are `static mut`,
//! touched only inside eval, which runs exclusively under the eval mutex --
//! single-writer by construction, never from irq context.
//!
//! Walk route (beats-decisions.md, verified `__ksymtab` exports): circular
//! `tasks` walk from `current` under RCU (`rust_helper_rcu_read_lock`,
//! helpers take no sleepable locks) with `get_task_struct` refs per task;
//! per-task fds via `iterate_fd` (handles its own `file_lock`, never
//! sleeps); unix sockets identified with `sock_from_file` +
//! `ops->family == AF_UNIX`; peers via `unix_peer_get` matched against the
//! walk's own `sk` table (the `sock` struct is opaque in bindings, so no
//! direct peer-queue reads -- the pointer-identity join needs no `sock`
//! internals); the extra peer ref is dropped with an in-module `sock_put`
//! equivalent (`rust_helper_refcount_dec_and_test` + `sk_free` on `sk_refcnt`
//! at `SK_REFCOUNT_OFFSET` == 128, pinned-tree verified; offset 0 is
//! `skc_addrpair`, never the refcount). `mm` is pinned with `get_task_mm` (non-sleeping)
//! and exe/memfd detail is resolved AFTER `rcu_read_unlock` (may sleep:
//! `get_file_rcu`, `fput`, `mmput`). Only thread-group leaders are recorded
//! (`pid == tgid`), matching userspace `all_processes` (leaders + kthreads).
//!
//! `fileless` = (exe unlinked [`i_nlink == 0`, the deletion invariant] OR
//! memfd [tmpfs magic + `memfd:` dentry-name prefix]) AND holds a socket.
//! Kernel threads (`mm == NULL`) and tasks without sockets never match.
//! `unix` lines render the name as `-` (names live in `unix_sock`, absent
//! from bindings) and owners capped at 8 pids per socket (extras dropped,
//! documented; the fixture uses 2).
//!
//! KNOWN DEMO-ONLY RACE (same class as the beats-blessed design): other
//! tasks' `files_struct` is read under RCU without a files ref. A full
//! ref/unref pair is out of reach on this tree: `put_files_struct` is NOT
//! exported (present in vmlinux text, but no `__ksymtab` entry and absent from
//! `Module.symvers`), so a hand-rolled `atomic_inc_not_zero` get-half could
//! never be balanced -- taking it alone would leak a `files_struct` ref per
//! task per walk. Mitigation in-module: tasks already `PF_EXITING` are skipped
//! before their `files` pointer is read (narrows the window, does not close
//! it). A task exiting mid-walk could still free its table during
//! `iterate_fd`. Window is one walk (~ms); `insmod` remains Wes's call, and
//! the talk must call this "racy by design, Wes accepted" rather than letting
//! row 2 discover it.
//!
//! Arithmetic: `+`/`-` use `checked_add`/`checked_sub` and fail the eval
//! with `err integer overflow` instead of trapping. Integer rendering is
//! hand-rolled decimal over unsigned division by a constant (no
//! `core::fmt` integer formatting anywhere in module code). A stage typo
//! like `9999999999999999999` fails `i64` parsing and falls through to
//! `err undefined word: ...`, exactly like userspace.
//!
//! Cursed words (Wes ruling 2026-11-02): `do_exit`, `panic`,
//! `emergency_restart`, `kernel_restart`, `orderly_poweroff` — ALL built,
//! address-only by default (`CURSED_ARMED` starts false at every insmod).
//! `arm` / `disarm` / `armed?` flip the toggle from the repl (easy, as
//! ruled; still root-only behind 0600). Fully-armed versions are wanted
//! eventually, not now: when armed, the word actually calls the kernel
//! function (`do_exit`/`panic`/reboot never return; `orderly_poweroff`
//! schedules and returns). Casting (which cursed word earns the laugh) is
//! deferred to Wes's final edit pass; all of them stay in the palette.
//!
//! kprobe resolve (narration rule): "we ask the kernel for the address via
//! a kprobe, then disarm it." Never "we iterate kallsyms"
//! (`kallsyms_on_each_symbol` is unexported; that route is retired).
//! `ksyms` prints the resolved `kallsyms_lookup_name`; `slab-caches` prints
//! the unexported list_head; `slabs` walks it (spike, go/no-go tonight).

use kernel::alloc::flags::GFP_KERNEL;
use kernel::bindings::{
    dentry, file, file_operations, inode, list_head, mm_struct, refcount_struct, sock, socket,
    sysinfo, task_struct, umode_t, AF_UNIX, TMPFS_MAGIC,
};
use kernel::prelude::*;
use kernel::sync::Mutex;
use kernel::uaccess::{UserPtr, UserSlice};
use kernel::{c_str, static_lock_class};

use core::ffi::{c_int, c_uint, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

/// Max bytes accepted per write, newline included. Longer writes get `-E2BIG`.
const MAX_LINE: usize = 4096;
/// Max response bytes held for the next read. `unix` dumps on busy machines
/// can exceed this; the eval then fails cleanly with `err output too large`
/// (never a torn prefix). Fixture sentences need a few hundred bytes.
const OUT_MAX: usize = 32768;
/// Data-stack depth. Pushing past this yields `err stack overflow`.
const MAX_STACK: usize = 64;
/// Walk caps. With both slots live and no free buffer the producer word
/// fails with `err no buffer`; a walk that would exceed a cap fails the eval
/// with `err walk overflow` (partial data is never rendered).
const MAX_UNIX: usize = 2048;
const MAX_TASKS: usize = 2048;
const MAX_INTS: usize = 2048;
/// Owners recorded per unix socket (extras dropped; fixture uses <= 2).
const MAX_OWNERS: usize = 8;
/// dentry name bytes compared for the `memfd:` prefix.
const MEMFD_PREFIX: &[u8; 6] = b"memfd:";
/// `PF_EXITING` (`include/linux/sched.h`): a task with this flag is already on
/// its way out, so the walk skips it before reading its `files` pointer
/// (narrows the files_struct race; see module docs).
const PF_EXITING: u32 = 0x00000004;

// Manual extern declaration (Step-1 pattern proof). The generated bindings
// also declare `do_exit`; redeclaring here is harmless and documents the
// exact signature the word relies on. Address-only unless `CURSED_ARMED`:
// invoking it ends the calling task (the write(2) context).
extern "C" {
    fn do_exit(code: core::ffi::c_long) -> !;
}

// Cursed reboot words: exported (`__ksymtab` verified OTP-D / Module.symvers)
// but with no binding declaration. Address-only unless armed.
// `orderly_poweroff` RETURNS (it schedules a workqueue); the other two never
// return. `kernel_restart` takes NULL for the default restart command.
extern "C" {
    fn emergency_restart() -> !;
    fn kernel_restart(cmd: *mut u8) -> !;
    fn orderly_poweroff(force: bool);
}

// kprobe resolver: exported, no bindings. Used ONLY in `kprobe_resolve`
// (register, copy `addr`, unregister immediately — never leave it armed).
// This is the narration: "we ask the kernel for the address via a kprobe,
// then disarm it." Never "we iterate kallsyms" (`kallsyms_on_each_symbol`
// is unexported on this kernel; that route is retired).
extern "C" {
    fn register_kprobe(kp: *mut KProbe) -> c_int;
    fn unregister_kprobe(kp: *mut KProbe);
}

/// Cursed-word safety toggle (Wes ruling 2026-11-02: build ALL of them,
/// address-only by default, fully armed later when Wes says so; the toggle
/// must be easy to flip).
///
/// Default `false` at every insmod. Flip from the repl: `arm` / `disarm`.
/// Query with `armed?`. Root-only behind the 0600 node.
static CURSED_ARMED: AtomicBool = AtomicBool::new(false);

/// `offsetof(struct kmem_cache, name)` — pinned-tree BTF (pahole over
/// `/sys/kernel/btf/vmlinux`, 7.2.3-zen1, 2026-11-02). Re-verify before
/// shipping if the tree moves.
const KMEM_CACHE_NAME_OFF: usize = 88;
/// `offsetof(struct kmem_cache, list)`
const KMEM_CACHE_LIST_OFF: usize = 96;
/// `offsetof(struct kmem_cache, size)` (object size including metadata)
const KMEM_CACHE_SIZE_OFF: usize = 24;
const _: () = assert!(
    KMEM_CACHE_NAME_OFF == 88 && KMEM_CACHE_LIST_OFF == 96 && KMEM_CACHE_SIZE_OFF == 24,
    "kmem_cache offsets changed: re-run pahole over BTF before shipping"
);

/// x86_64 kernel-virtual lower bound for a plausible pointer. Used to stop
/// a bad list walk before it derefs garbage (spike discipline: fail the
/// eval, never guess).
const KERN_ADDR_MIN: usize = 0xffff800000000000;

/// Minimal `struct kprobe` enough for `register_kprobe` to fill `addr` from
/// `symbol_name`. Layout follows `include/linux/kprobes.h` (7.2.3-zen1):
/// hlist_node + list_head + nmissed + addr + symbol_name + offset + pad +
/// pre_handler + post_handler, then a generous zeroed tail for `opcode`,
/// `arch_specific_insn` and `flags` (the kernel writes those; the buffer
/// must be large enough or register scribbles past the allocation).
#[repr(C)]
struct KProbe {
    hlist: [u64; 2],
    list: [u64; 2],
    nmissed: u64,
    addr: *mut u8,
    symbol_name: *const u8,
    offset: u32,
    _pad: u32,
    pre_handler: Option<unsafe extern "C" fn(*mut KProbe, *mut c_void) -> c_int>,
    post_handler: *mut c_void,
    /// Zeroed tail: opcode + arch_specific_insn + flags. 64 u64 = 512 B,
    /// well above the ~136 B the kernel needs on this arch/config.
    tail: [u64; 64],
}

/// No-op pre-handler. Registering with a NULL handler is the LKRG-style
/// lookup trick on some trees; a real no-op is the conservative choice
/// (the probe is unregistered immediately; the window is one int3).
unsafe extern "C" fn kprobe_nop(_p: *mut KProbe, _regs: *mut c_void) -> c_int {
    0
}

// Manual extern declarations: exported (`__ksymtab` verified) but with no
// binding declaration (bindgen blocklists/emits none of these as callable).
// `improper_ctypes`: the kernel structs are opaque here by design (we only
// ever pass pointers, never values); the warning is allowed, not ignored.
#[allow(improper_ctypes)]
extern "C" {
    fn unix_peer_get(sk: *mut sock) -> *mut sock;
    fn sk_free(sk: *mut sock);
    fn rust_helper_get_current() -> *mut task_struct;
    fn rust_helper_get_task_struct(t: *mut task_struct);
    fn rust_helper_put_task_struct(t: *mut task_struct);
    fn rust_helper_rcu_read_lock();
    fn rust_helper_rcu_read_unlock();
    fn rust_helper_refcount_dec_and_test(v: *mut refcount_struct) -> bool;
}

/// Offset of `sk_refcnt` (`sk->__sk_common.skc_refcnt`) within `struct sock`.
///
/// Verified against the pinned 7.2.3-zen tree, not assumed: `include/net/sock.h`
/// forces `offset(struct sock, sk_refcnt) == 128` on 64-bit with `CONFIG_IPV6=y`
/// (padding comment above `skc_flags`), `__sk_common` is the first member of
/// `struct sock`, and the pinned `.config` has both `CONFIG_IPV6=y` and
/// `CONFIG_SOCK_RX_QUEUE_MAPPING=y`. A scratch `static_assert(offsetof(struct
/// sock, sk_refcnt) == 128)` plus sized-commons (`nm -S`: `sk_refcnt` 0x80,
/// `skc_net` 0x30) compiled through the same pinned kbuild confirm it (see the
/// OTP-FIX-batch receipt). Offset 0 is `skc_addrpair`, NOT the refcount -- the
/// old offset-0 put decremented socket addresses as a refcount; never use 0.
const SK_REFCOUNT_OFFSET: usize = 128;
const _: () = assert!(
    SK_REFCOUNT_OFFSET == 128,
    "sk_refcnt offset changed: re-verify against include/net/sock.h before shipping"
);

/// `sock_put` equivalent: `refcount_dec_and_test` on `sk_refcnt` + `sk_free`.
/// Non-sleeping (refcount op + free-on-zero), safe under RCU.
unsafe fn sock_put(sk: *mut sock) {
    // SAFETY: the offset is verified above; `sk` came from `unix_peer_get`
    // (one live ref). Only this function derives a `refcount_t` from a `sock`
    // pointer (the walk table never passes its `sk` here).
    unsafe {
        let refcnt = (sk as *mut u8).wrapping_add(SK_REFCOUNT_OFFSET) as *mut refcount_struct;
        if rust_helper_refcount_dec_and_test(refcnt) {
            sk_free(sk);
        }
    }
}

/// Shared repl state behind the single-writer mutex.
struct Inner {
    /// Last complete response, valid for `out_len` bytes.
    out: [u8; OUT_MAX],
    out_len: usize,
    /// Set after the first eval; reads before that return EOF (zero bytes).
    has_output: bool,
}

/// Byte buffer with checked appends that report overflow (no allocator in kernel).
struct BufWriter<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        BufWriter { buf, len: 0 }
    }

    fn reset(&mut self) {
        self.len = 0;
    }

    fn finish(self) -> usize {
        self.len
    }

    /// Append a slice; `Err(())` when it would not fit. Total by construction:
    /// the range is pre-checked and the copy uses iterators only.
    fn append(&mut self, bytes: &[u8]) -> Result<(), ()> {
        let new_len = self.len.checked_add(bytes.len()).ok_or(())?;
        let dst = self.buf.get_mut(self.len..new_len).ok_or(())?;
        for (d, s) in dst.iter_mut().zip(bytes.iter()) {
            *d = *s;
        }
        self.len = new_len;
        Ok(())
    }

    fn append_str(&mut self, s: &str) -> Result<(), ()> {
        self.append(s.as_bytes())
    }

    /// Hand-rolled u64 decimal (no `core::fmt` integer formatting: its
    /// monomorphized arithmetic is what pulled `panic_const_*_overflow`
    /// into Step-1 via the old transport adapter). Division/modulo use a
    /// constant divisor, which carries no overflow or zero check.
    fn append_u64(&mut self, mut v: u64) -> Result<(), ()> {
        let mut digits = [0u8; 20];
        let mut n = 0usize;
        if v == 0 {
            digits[0] = b'0';
            n = 1;
        } else {
            while v != 0 {
                if n >= digits.len() {
                    return Err(());
                }
                let d = v % 10;
                v /= 10;
                digits[n] = b'0'.wrapping_add(d as u8);
                n = n.checked_add(1).ok_or(())?;
            }
        }
        let mut i = n;
        while i != 0 {
            i = i.checked_sub(1).ok_or(())?;
            match digits.get(i) {
                Some(b) => self.append(&[*b])?,
                None => return Err(()),
            }
        }
        Ok(())
    }

    /// Hand-rolled u64 lowercase hex (no prefix, no padding): the same
    /// no-`core::fmt`, no-panic discipline as `append_u64` above. Used by
    /// `w_do_exit` so the `0x` prefix it prints is truthful hex, not decimal.
    fn append_u64_hex(&mut self, mut v: u64) -> Result<(), ()> {
        let mut digits = [0u8; 16];
        let mut n = 0usize;
        if v == 0 {
            digits[0] = b'0';
            n = 1;
        } else {
            while v != 0 {
                if n >= digits.len() {
                    return Err(());
                }
                let d = (v & 0xf) as u8;
                digits[n] = if d < 10 {
                    b'0'.wrapping_add(d)
                } else {
                    b'a'.wrapping_add(d - 10)
                };
                v >>= 4;
                n = n.checked_add(1).ok_or(())?;
            }
        }
        let mut i = n;
        while i != 0 {
            i = i.checked_sub(1).ok_or(())?;
            match digits.get(i) {
                Some(b) => self.append(&[*b])?,
                None => return Err(()),
            }
        }
        Ok(())
    }

    fn append_i64(&mut self, v: i64) -> Result<(), ()> {
        if v < 0 {
            self.append(b"-")?;
            self.append_u64((v as u64).wrapping_neg())
        } else {
            self.append_u64(v as u64)
        }
    }
}

/// Word-level failure kinds, rendered as `err <message>` lines.
enum WordErr {
    Underflow,
    StackOverflow,
    Output,
    IntOverflow,
    WalkOverflow,
    NoBuffer,
    /// Type error in the named word: `err type error in <name>`.
    Type(&'static str),
    /// `register_kprobe` failed (non-zero) or returned a NULL addr.
    Kprobe,
    /// kallsyms_lookup_name (via the kprobe-resolved pointer) returned 0.
    Resolve,
}

impl WordErr {
    fn msg(self) -> &'static str {
        match self {
            WordErr::Underflow => "stack underflow",
            WordErr::StackOverflow => "stack overflow",
            WordErr::Output => "output too large",
            WordErr::IntOverflow => "integer overflow",
            WordErr::WalkOverflow => "walk overflow",
            WordErr::NoBuffer => "no buffer",
            WordErr::Type(_) => "type error in ",
            WordErr::Kprobe => "kprobe failed",
            WordErr::Resolve => "symbol not found",
        }
    }
}

/// One unix socket seen in the walk. `sk` is only valid during the walk
/// (cleared right after peer resolution); never dereferenced afterwards.
#[derive(Copy, Clone)]
struct UnixRec {
    ino: u64,
    sk: *mut sock,
    peer: u64,
    owners: [u32; MAX_OWNERS],
    nowners: u8,
}

/// One thread-group leader seen in the walk. `mm` is a live `get_task_mm`
/// ref only between the RCU section and exe resolution (cleared after).
#[derive(Copy, Clone)]
struct TaskRec {
    pid: u32,
    uid: u32,
    comm: [u8; 16],
    mm: *mut mm_struct,
    exe_deleted: bool,
    has_sock: bool,
    has_memfd: bool,
    fileless: bool,
}

/// Scratch buffers, `[2]` slots each. Touched only inside eval (exclusive
/// under the eval mutex); `static mut` access is unsafe and documented here.
static mut UNIX_BUF: [[UnixRec; MAX_UNIX]; 2] = [[UnixRec {
    ino: 0,
    sk: core::ptr::null_mut(),
    peer: 0,
    owners: [0; MAX_OWNERS],
    nowners: 0,
}; MAX_UNIX]; 2];
static mut TASK_BUF: [[TaskRec; MAX_TASKS]; 2] = [[TaskRec {
    pid: 0,
    uid: 0,
    comm: [0; 16],
    mm: core::ptr::null_mut(),
    exe_deleted: false,
    has_sock: false,
    has_memfd: false,
    fileless: false,
}; MAX_TASKS]; 2];
static mut INT_BUF: [[i64; MAX_INTS]; 2] = [[0i64; MAX_INTS]; 2];

const KIND_UNIX: u8 = 0;
const KIND_TASKS: u8 = 1;
const KIND_INTS: u8 = 2;

/// Stack value: scalar or a view `{kind, slot, n}` into the scratch buffers.
#[derive(Copy, Clone)]
enum Val {
    Int(i64),
    Col { kind: u8, slot: u8, n: usize },
}

impl Val {
    fn tag(self) -> &'static str {
        match self {
            Val::Int(_) => "Int",
            Val::Col { kind: KIND_UNIX, .. } => "Unix",
            Val::Col {
                kind: KIND_TASKS, ..
            } => "Tasks",
            _ => "Ints",
        }
    }

    fn len(self) -> usize {
        match self {
            Val::Int(_) => 1,
            Val::Col { n, .. } => n,
        }
    }
}

fn pop(stack: &[Val; MAX_STACK], depth: &mut usize) -> Result<Val, WordErr> {
    if *depth == 0 {
        return Err(WordErr::Underflow);
    }
    *depth = depth.checked_sub(1).ok_or(WordErr::Underflow)?;
    match stack.get(*depth) {
        Some(v) => Ok(*v),
        // Not reachable while the push guard below holds; kept total so no
        // failure mode can ever trap.
        None => Err(WordErr::Output),
    }
}

fn push(stack: &mut [Val; MAX_STACK], depth: &mut usize, v: Val) -> Result<(), WordErr> {
    if *depth >= MAX_STACK {
        return Err(WordErr::StackOverflow);
    }
    match stack.get_mut(*depth) {
        Some(slot) => {
            *slot = v;
            *depth = depth.checked_add(1).ok_or(WordErr::StackOverflow)?;
            Ok(())
        }
        // Same note as in `pop`: guarded above, total by construction.
        None => Err(WordErr::Output),
    }
}

/// Pick the buffer slot no live stack value of this kind references.
/// Clean `NoBuffer` instead of aliasing when both slots are live.
fn free_slot(stack: &[Val; MAX_STACK], depth: usize, kind: u8) -> Result<u8, WordErr> {
    let mut used0 = false;
    let mut used1 = false;
    let mut i = 0usize;
    while i < depth {
        match stack.get(i) {
            Some(Val::Col { kind: k, slot: s, .. }) if *k == kind => {
                if *s == 0 {
                    used0 = true;
                } else {
                    used1 = true;
                }
            }
            Some(_) => {}
            None => return Err(WordErr::Output),
        }
        i = i.checked_add(1).ok_or(WordErr::Output)?;
    }
    if !used0 {
        Ok(0)
    } else if !used1 {
        Ok(1)
    } else {
        Err(WordErr::NoBuffer)
    }
}

fn slot_unix(slot: u8) -> Result<&'static mut [UnixRec; MAX_UNIX], WordErr> {
    // SAFETY: eval-exclusive (mutex) by the module's documented discipline.
    unsafe {
        match slot {
            0 => Ok(&mut UNIX_BUF[0]),
            _ => Ok(&mut UNIX_BUF[1]),
        }
    }
}

fn slot_tasks(slot: u8) -> Result<&'static mut [TaskRec; MAX_TASKS], WordErr> {
    // SAFETY: same discipline as `slot_unix`.
    unsafe {
        match slot {
            0 => Ok(&mut TASK_BUF[0]),
            _ => Ok(&mut TASK_BUF[1]),
        }
    }
}

fn slot_ints(slot: u8) -> Result<&'static mut [i64; MAX_INTS], WordErr> {
    // SAFETY: same discipline as `slot_unix`.
    unsafe {
        match slot {
            0 => Ok(&mut INT_BUF[0]),
            _ => Ok(&mut INT_BUF[1]),
        }
    }
}

/// Single-record indexed access, so copies never hold two borrows on the
/// same static at once (the borrow checker cannot see disjoint slots).
unsafe fn unix_get(slot: u8, i: usize) -> Result<UnixRec, WordErr> {
    unsafe {
        let buf = match slot {
            0 => &UNIX_BUF[0],
            _ => &UNIX_BUF[1],
        };
        match buf.get(i) {
            Some(r) => Ok(*r),
            None => Err(WordErr::Output),
        }
    }
}

unsafe fn unix_set(slot: u8, i: usize, v: UnixRec) -> Result<(), WordErr> {
    unsafe {
        let buf = match slot {
            0 => &mut UNIX_BUF[0],
            _ => &mut UNIX_BUF[1],
        };
        match buf.get_mut(i) {
            Some(d) => {
                *d = v;
                Ok(())
            }
            None => Err(WordErr::Output),
        }
    }
}

unsafe fn tasks_get(slot: u8, i: usize) -> Result<TaskRec, WordErr> {
    unsafe {
        let buf = match slot {
            0 => &TASK_BUF[0],
            _ => &TASK_BUF[1],
        };
        match buf.get(i) {
            Some(r) => Ok(*r),
            None => Err(WordErr::Output),
        }
    }
}

unsafe fn tasks_set(slot: u8, i: usize, v: TaskRec) -> Result<(), WordErr> {
    unsafe {
        let buf = match slot {
            0 => &mut TASK_BUF[0],
            _ => &mut TASK_BUF[1],
        };
        match buf.get_mut(i) {
            Some(d) => {
                *d = v;
                Ok(())
            }
            None => Err(WordErr::Output),
        }
    }
}

unsafe fn ints_get(slot: u8, i: usize) -> Result<i64, WordErr> {
    unsafe {
        let buf = match slot {
            0 => &INT_BUF[0],
            _ => &INT_BUF[1],
        };
        match buf.get(i) {
            Some(r) => Ok(*r),
            None => Err(WordErr::Output),
        }
    }
}

unsafe fn ints_set(slot: u8, i: usize, v: i64) -> Result<(), WordErr> {
    unsafe {
        let buf = match slot {
            0 => &mut INT_BUF[0],
            _ => &mut INT_BUF[1],
        };
        match buf.get_mut(i) {
            Some(d) => {
                *d = v;
                Ok(())
            }
            None => Err(WordErr::Output),
        }
    }
}

/// Append one fully staged line atomically: either the whole line lands or
/// nothing does, so output is never a torn prefix.
fn emit_staged(out: &mut BufWriter<'_>, stage: &[u8], n: usize) -> Result<(), WordErr> {
    match stage.get(..n) {
        Some(line) => out.append(line).map_err(|_| WordErr::Output),
        None => Err(WordErr::Output),
    }
}

/// Emit one `int <n>` line. Pure output helper: it touches no stack (the stack
/// effect lives with the caller, e.g. leftover-stack rendering).
fn emit_int(out: &mut BufWriter<'_>, n: i64) -> Result<(), WordErr> {
    let mut stage = [0u8; 32];
    let nbytes = {
        let mut w = BufWriter::new(&mut stage);
        w.append(b"int ").map_err(|_| WordErr::Output)?;
        w.append_i64(n).map_err(|_| WordErr::Output)?;
        w.append(b"\n").map_err(|_| WordErr::Output)?;
        w.finish()
    };
    emit_staged(out, &stage, nbytes)
}

/// Emit `ints <n...>` (possibly empty) straight into `out`. A failed eval
/// discards everything (`emit_err` resets), so mid-line overflow needs no
/// staging -- the response is never a torn prefix on the wire.
fn emit_ints(out: &mut BufWriter<'_>, vals: &[i64]) -> Result<(), WordErr> {
    out.append(b"ints").map_err(|_| WordErr::Output)?;
    let mut i = 0usize;
    while i < vals.len() {
        match vals.get(i) {
            Some(v) => {
                out.append(b" ").map_err(|_| WordErr::Output)?;
                out.append_i64(*v).map_err(|_| WordErr::Output)?;
            }
            None => return Err(WordErr::Output),
        }
        i = i.checked_add(1).ok_or(WordErr::Output)?;
    }
    out.append(b"\n").map_err(|_| WordErr::Output)
}

/// Emit one `unix <ino> - <owners,csv|-> <peer|->` line, straight into `out`
/// (same discard-on-failure discipline as `emit_ints`).
fn emit_unix_rec(out: &mut BufWriter<'_>, r: &UnixRec) -> Result<(), WordErr> {
    out.append(b"unix ").map_err(|_| WordErr::Output)?;
    out.append_u64(r.ino).map_err(|_| WordErr::Output)?;
    // Names live in `unix_sock` (absent from bindings): always `-`.
    out.append(b" - ").map_err(|_| WordErr::Output)?;
    if r.nowners == 0 {
        out.append(b"-").map_err(|_| WordErr::Output)?;
    } else {
        let mut i = 0u8;
        while i < r.nowners {
            if i != 0 {
                out.append(b",").map_err(|_| WordErr::Output)?;
            }
            match r.owners.get(i as usize) {
                Some(o) => out.append_u64(*o as u64).map_err(|_| WordErr::Output)?,
                None => return Err(WordErr::Output),
            }
            i = i.checked_add(1).ok_or(WordErr::Output)?;
        }
    }
    out.append(b" ").map_err(|_| WordErr::Output)?;
    if r.peer == 0 {
        out.append(b"-").map_err(|_| WordErr::Output)?;
    } else {
        out.append_u64(r.peer).map_err(|_| WordErr::Output)?;
    }
    out.append(b"\n").map_err(|_| WordErr::Output)
}

/// Emit one `task <pid> <comm> <uid>` line, straight into `out` (same
/// discard-on-failure discipline); comm is NUL-truncated and non-UTF8 bytes
/// render as `?` (the response must stay valid UTF-8).
fn emit_task_rec(out: &mut BufWriter<'_>, pid: u32, uid: u32, comm: &[u8; 16]) -> Result<(), WordErr> {
    out.append(b"task ").map_err(|_| WordErr::Output)?;
    out.append_u64(pid as u64).map_err(|_| WordErr::Output)?;
    out.append(b" ").map_err(|_| WordErr::Output)?;
    let mut len = 0usize;
    while len < comm.len() {
        match comm.get(len) {
            Some(0) | None => break,
            Some(_) => {}
        }
        len = len.checked_add(1).ok_or(WordErr::Output)?;
    }
    match comm.get(..len) {
        Some(raw) => {
            for b in raw.iter() {
                let c = *b;
                if (0x20..0x7f).contains(&c) {
                    out.append(&[c]).map_err(|_| WordErr::Output)?;
                } else {
                    out.append(b"?").map_err(|_| WordErr::Output)?;
                }
            }
        }
        None => return Err(WordErr::Output),
    }
    out.append(b" ").map_err(|_| WordErr::Output)?;
    out.append_u64(uid as u64).map_err(|_| WordErr::Output)?;
    out.append(b"\n").map_err(|_| WordErr::Output)
}

/// Emit `text <payload>`.
fn emit_text(out: &mut BufWriter<'_>, payload: &str) -> Result<(), WordErr> {
    let mut stage = [0u8; 64];
    let nbytes = {
        let mut w = BufWriter::new(&mut stage);
        w.append(b"text ").map_err(|_| WordErr::Output)?;
        w.append_str(payload).map_err(|_| WordErr::Output)?;
        w.append(b"\n").map_err(|_| WordErr::Output)?;
        w.finish()
    };
    emit_staged(out, &stage, nbytes)
}

/// Render one stack value's line(s), used by both `.` and leftover rendering.
fn render_val(out: &mut BufWriter<'_>, v: Val) -> Result<(), WordErr> {
    match v {
        Val::Int(n) => emit_int(out, n),
        Val::Col { kind: KIND_INTS, slot, n } => {
            let buf = slot_ints(slot)?;
            let vals = buf.get(..n).ok_or(WordErr::Output)?;
            emit_ints(out, vals)
        }
        Val::Col { kind: KIND_UNIX, slot, n } => {
            let buf = slot_unix(slot)?;
            let mut i = 0usize;
            while i < n {
                match buf.get(i) {
                    Some(r) => {
                        let rec = *r;
                        emit_unix_rec(out, &rec)?;
                    }
                    None => return Err(WordErr::Output),
                }
                i = i.checked_add(1).ok_or(WordErr::Output)?;
            }
            Ok(())
        }
        Val::Col { kind: KIND_TASKS, slot, n } => {
            let buf = slot_tasks(slot)?;
            let mut i = 0usize;
            while i < n {
                match buf.get(i) {
                    Some(r) => {
                        let (pid, uid, comm) = (r.pid, r.uid, r.comm);
                        emit_task_rec(out, pid, uid, &comm)?;
                    }
                    None => return Err(WordErr::Output),
                }
                i = i.checked_add(1).ok_or(WordErr::Output)?;
            }
            Ok(())
        }
        _ => Err(WordErr::Output),
    }
}

/// Truncate-safe error line writer: reset, then `err <head><tail>\n`. By the
/// size argument (head under 32 bytes, tail at most one 4096-byte token) the
/// result always fits in `OUT_MAX`, so the sentinel is always well-formed.
fn emit_err(out: &mut BufWriter<'_>, head: &[u8], tail: &[u8]) {
    out.reset();
    let _ = out.append(head);
    let _ = out.append(tail);
    let _ = out.append(b"\n");
}

// ---------------------------------------------------------------------------
// Walk machinery.
// ---------------------------------------------------------------------------

/// Per-eval walk context, threaded through `iterate_fd` (synchronously, on
/// the eval stack -- never escapes the eval).
struct WalkCtx {
    tslot: u8,
    uslot: u8,
    ntasks: usize,
    nunix: usize,
    /// Index of the task currently being fd-walked (`usize::MAX` = none).
    cur: usize,
    overflow: bool,
}

/// `iterate_fd` callback: classify one fd of `ctx.cur`. Non-sleeping:
/// pointer reads plus bounded static-buffer appends only.
unsafe extern "C" fn fd_cb(data: *const c_void, file: *mut file, _fd: c_uint) -> c_int {
    // SAFETY: `data` is `&mut WalkCtx` on the eval stack, callback is
    // synchronous inside `iterate_fd`; buffers are eval-exclusive.
    unsafe {
        let ctx = &mut *(data as *mut WalkCtx);
        if ctx.cur == usize::MAX {
            return 0;
        }
        let tasks = match slot_tasks(ctx.tslot) {
            Ok(b) => b,
            Err(_) => {
                ctx.overflow = true;
                return 0;
            }
        };
        let trec = match tasks.get_mut(ctx.cur) {
            Some(t) => t,
            None => {
                ctx.overflow = true;
                return 0;
            }
        };
        if file.is_null() {
            return 0;
        }
        let finode = core::ptr::addr_of!((*file).f_inode).read();
        if finode.is_null() {
            return 0;
        }
        let ino = core::ptr::addr_of!((*finode).i_ino).read();
        // Socket? (any family sets has_sock; AF_UNIX also joins the table).
        // `sock_from_file` yields the `socket`; the `sock` hangs off it.
        let sockp: *mut socket = kernel::bindings::sock_from_file(file);
        if !sockp.is_null() {
            trec.has_sock = true;
            let sk = core::ptr::addr_of!((*sockp).sk).read();
            if !sk.is_null() {
            let ops = core::ptr::addr_of!((*sockp).ops).read();
            let mut is_unix = false;
            if !ops.is_null() {
                let fam = core::ptr::addr_of!((*ops).family).read();
                is_unix = fam == AF_UNIX as c_int;
            }
            if is_unix {
                let ubuf = match slot_unix(ctx.uslot) {
                    Ok(b) => b,
                    Err(_) => {
                        ctx.overflow = true;
                        return 0;
                    }
                };
                // Find-or-append by ino.
                let mut idx = 0usize;
                let mut found = false;
                while idx < ctx.nunix {
                    match ubuf.get(idx) {
                        Some(r) if r.ino == ino => {
                            found = true;
                            break;
                        }
                        Some(_) => {}
                        None => {
                            ctx.overflow = true;
                            return 0;
                        }
                    }
                    match idx.checked_add(1) {
                        Some(n) => idx = n,
                        None => {
                            ctx.overflow = true;
                            return 0;
                        }
                    }
                }
                if !found {
                    if ctx.nunix >= MAX_UNIX {
                        ctx.overflow = true;
                        return 0;
                    }
                    match ubuf.get_mut(ctx.nunix) {
                        Some(r) => {
                            r.ino = ino;
                            r.sk = sk;
                            r.peer = 0;
                            r.nowners = 0;
                        }
                        None => {
                            ctx.overflow = true;
                            return 0;
                        }
                    }
                    idx = ctx.nunix;
                    match ctx.nunix.checked_add(1) {
                        Some(n) => ctx.nunix = n,
                        None => {
                            ctx.overflow = true;
                            return 0;
                        }
                    }
                }
                // Record owner pid (cap; extras dropped).
                if let Some(r) = ubuf.get_mut(idx) {
                    if r.nowners < MAX_OWNERS as u8 {
                        if let Some(o) = r.owners.get_mut(r.nowners as usize) {
                            if let Some(t2) = tasks.get(ctx.cur) {
                                *o = t2.pid;
                            }
                            match r.nowners.checked_add(1) {
                                Some(n) => r.nowners = n,
                                None => {}
                            }
                        }
                    }
                    // `sk` refresh: same socket, keep first pointer.
                    if r.sk.is_null() {
                        r.sk = sk;
                    }
                }
            }
            }
        }
        // memfd? tmpfs magic + `memfd:` dentry-name prefix (precise:
        // plain /dev/shm files share the magic but not the prefix).
        let sb = core::ptr::addr_of!((*finode).i_sb).read();
        if !sb.is_null() {
            let magic = core::ptr::addr_of!((*sb).s_magic).read();
            if magic == TMPFS_MAGIC as usize {
                let dent = core::ptr::addr_of!((*file).__bindgen_anon_1.f_path.dentry).read();
                if !dent.is_null() {
                    let name = core::ptr::addr_of!((*dent).__bindgen_anon_1.d_name.name).read();
                    let len = core::ptr::addr_of!((*dent).__bindgen_anon_1.d_name.__bindgen_anon_1)
                        .read()
                        .__bindgen_anon_1
                        .len;
                    if !name.is_null() && len >= MEMFD_PREFIX.len() as u32 {
                        let mut ok = true;
                        let mut i = 0usize;
                        while i < MEMFD_PREFIX.len() {
                            let want = match MEMFD_PREFIX.get(i) {
                                Some(b) => *b,
                                None => {
                                    ok = false;
                                    break;
                                }
                            };
                            let got = *(name as *const u8).wrapping_add(i);
                            if got != want {
                                ok = false;
                                break;
                            }
                            match i.checked_add(1) {
                                Some(n) => i = n,
                                None => {
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        if ok {
                            if let Some(t) = tasks.get_mut(ctx.cur) {
                                t.has_memfd = true;
                            }
                        }
                    }
                }
            }
        }
        0
    }
}

/// Release every `mm` still pinned in task slot `tslot` and clear the field.
/// Called on ALL post-phase-1 error paths (overflow return, phase-2 slot
/// errors) so a failed walk never leaks an `mm_struct` (an `mmgrab` without
/// `mmdrop` pins the mm until reboot). Runs only AFTER `rcu_read_unlock`.
fn drain_mms(tslot: u8) {
    if let Ok(tasks) = slot_tasks(tslot) {
        let mut j = 0usize;
        while j < MAX_TASKS {
            match tasks.get_mut(j) {
                Some(r) => {
                    let mm = r.mm;
                    if !mm.is_null() {
                        // SAFETY: our `get_task_mm` ref, stored during phase 1.
                        unsafe { kernel::bindings::mmput(mm) };
                        r.mm = core::ptr::null_mut();
                    }
                }
                // Unreachable on the fixed-size buffer; stop rather than spin.
                None => break,
            }
            j = match j.checked_add(1) {
                Some(n) => n,
                None => break,
            };
        }
    }
}

/// Full machine walk into the given slots. Phase 1 runs under RCU (no
/// sleeping): task list + `iterate_fd` per task + `get_task_mm` pins + peer
/// resolution. Phase 2 runs after `rcu_read_unlock` (may sleep): exe
/// resolution via `get_file_rcu`/`fput`/`mmput`.
fn do_walk(ctx: &mut WalkCtx) -> Result<(), WordErr> {
    ctx.ntasks = 0;
    ctx.nunix = 0;
    ctx.cur = usize::MAX;
    ctx.overflow = false;

    // SAFETY: raw kernel walk, see module docs. RCU held across phase 1;
    // nothing inside it sleeps (spinlocks + refcounts + bounded stores only).
    unsafe {
        rust_helper_rcu_read_lock();
        let cur = rust_helper_get_current();
        if cur.is_null() {
            rust_helper_rcu_read_unlock();
            return Err(WordErr::WalkOverflow);
        }
        let start = core::ptr::addr_of!((*cur).tasks) as *mut list_head;
        let mut pos = core::ptr::addr_of!((*cur).tasks.next).read();
        let mut walked = 0usize;
        loop {
            if pos.is_null() || pos == start {
                break;
            }
            walked = match walked.checked_add(1) {
                Some(n) => n,
                // No `?` under the RCU read lock (it would leak the lock):
                // record and break; the drain path below the unlock reports it.
                None => {
                    ctx.overflow = true;
                    break;
                }
            };
            if walked > MAX_TASKS {
                ctx.overflow = true;
                break;
            }
            // container_of(tasks.next -> task_struct.tasks) by hand:
            // offset_of! never panics, wrapping_sub on *mut u8 never panics.
            let task = (pos as *mut u8)
                .wrapping_sub(core::mem::offset_of!(task_struct, tasks))
                as *mut task_struct;
            let next = core::ptr::addr_of!((*pos).next).read();
            rust_helper_get_task_struct(task);
            let pid = core::ptr::addr_of!((*task).pid).read();
            let tgid = core::ptr::addr_of!((*task).tgid).read();
            // Narrow the files_struct race (see module docs): a task already
            // exiting may free its table mid-`iterate_fd`, so skip it before
            // its `files` pointer is read. Narrows the window, does not close
            // it; quiescent guests never trip this (no behavior change there).
            let flags: u32 = core::ptr::addr_of!((*task).flags).read();
            if flags & PF_EXITING != 0 {
                rust_helper_put_task_struct(task);
                pos = next;
                continue;
            }
            if pid == tgid && ctx.ntasks < MAX_TASKS {
                let idx = ctx.ntasks;
                let cred_ptr = core::ptr::addr_of!((*task).cred).read();
                let mut uid = 0u32;
                if !cred_ptr.is_null() {
                    let euid: kernel::bindings::kuid_t =
                        core::ptr::addr_of!((*cred_ptr).euid).read();
                    uid = euid.val;
                }
                let comm_raw: [u8; 16] = core::ptr::addr_of!((*task).comm).read();
                let mut comm = [0u8; 16];
                let mut i = 0usize;
                while i < 16 {
                    match comm_raw.get(i) {
                        Some(c) => match comm.get_mut(i) {
                            Some(d) => *d = *c,
                            None => break,
                        },
                        None => break,
                    }
                    i = match i.checked_add(1) {
                        Some(n) => n,
                        None => break,
                    };
                }
                {
                    // No `?` under the RCU read lock (a task ref is held here):
                    // drop the ref and break to the drain path below.
                    let tasks = match slot_tasks(ctx.tslot) {
                        Ok(b) => b,
                        Err(_) => {
                            ctx.overflow = true;
                            rust_helper_put_task_struct(task);
                            break;
                        }
                    };
                    match tasks.get_mut(idx) {
                        Some(r) => {
                            r.pid = pid as u32;
                            r.uid = uid;
                            r.comm = comm;
                            r.mm = core::ptr::null_mut();
                            r.exe_deleted = false;
                            r.has_sock = false;
                            r.has_memfd = false;
                            r.fileless = false;
                        }
                        None => ctx.overflow = true,
                    }
                }
                if !ctx.overflow {
                    let files = core::ptr::addr_of!((*task).files).read();
                    if !files.is_null() {
                        ctx.cur = idx;
                        kernel::bindings::iterate_fd(
                            files,
                            0,
                            Some(fd_cb),
                            ctx as *mut WalkCtx as *const c_void,
                        );
                        ctx.cur = usize::MAX;
                    }
                    // `fd_cb` may have tripped overflow mid-`iterate_fd`: never
                    // pin an `mm` for a doomed walk (it would leak below).
                    if ctx.overflow {
                        rust_helper_put_task_struct(task);
                        break;
                    }
                    let mm = kernel::bindings::get_task_mm(task);
                    // No `?` under the RCU read lock (a task ref AND possibly
                    // a fresh `mm` pin are held here): release both, then break.
                    let tasks = match slot_tasks(ctx.tslot) {
                        Ok(b) => b,
                        Err(_) => {
                            ctx.overflow = true;
                            if !mm.is_null() {
                                // SAFETY: our fresh `get_task_mm` ref, never stored.
                                unsafe { kernel::bindings::mmput(mm) };
                            }
                            rust_helper_put_task_struct(task);
                            break;
                        }
                    };
                    if let Some(r) = tasks.get_mut(idx) {
                        r.mm = mm;
                    } else {
                        ctx.overflow = true;
                        if !mm.is_null() {
                            // SAFETY: our fresh `get_task_mm` ref, never stored.
                            unsafe { kernel::bindings::mmput(mm) };
                        }
                    }
                    if !ctx.overflow {
                        match ctx.ntasks.checked_add(1) {
                            Some(n) => ctx.ntasks = n,
                            None => ctx.overflow = true,
                        }
                    }
                }
            }
            rust_helper_put_task_struct(task);
            if ctx.overflow {
                break;
            }
            pos = next;
        }
        // Peer resolution while still under RCU (unix_peer_get takes only
        // the unix state spinlock; our sock_put replica never sleeps).
        // No `?` under the RCU read lock: on the (unreachable in practice)
        // slot error, skip resolution and let the drain path report it.
        if !ctx.overflow {
            match slot_unix(ctx.uslot) {
                Err(_) => ctx.overflow = true,
                Ok(ubuf) => {
            let mut i = 0usize;
            while i < ctx.nunix {
                let sk = match ubuf.get(i) {
                    Some(r) => r.sk,
                    None => {
                        ctx.overflow = true;
                        break;
                    }
                };
                let mut peer_ino = 0u64;
                if !sk.is_null() {
                    let p = unix_peer_get(sk);
                    if !p.is_null() {
                        let mut j = 0usize;
                        while j < ctx.nunix {
                            match ubuf.get(j) {
                                Some(r) if r.sk == p => {
                                    peer_ino = r.ino;
                                    break;
                                }
                                Some(_) => {}
                                None => {
                                    ctx.overflow = true;
                                    // The peer ref is live: drop it before
                                    // breaking or the sock leaks.
                                    sock_put(p);
                                    break;
                                }
                            }
                            j = match j.checked_add(1) {
                                Some(n) => n,
                                None => {
                                    ctx.overflow = true;
                                    // Same live-peer-ref drain as above.
                                    sock_put(p);
                                    break;
                                }
                            };
                        }
                        sock_put(p);
                    }
                }
                match ubuf.get_mut(i) {
                    Some(r) => {
                        r.peer = peer_ino;
                        r.sk = core::ptr::null_mut();
                    }
                    None => {
                        ctx.overflow = true;
                        break;
                    }
                }
                i = match i.checked_add(1) {
                    Some(n) => n,
                    None => {
                        ctx.overflow = true;
                        break;
                    }
                };
            }
                }
            }
        }
        rust_helper_rcu_read_unlock();
    }
    // Overflow unwind: every `mm` pinned in phase 1 is dropped here, AFTER
    // `rcu_read_unlock` above (`mmput` may sleep, and no lock is held here
    // but the sleepable eval mutex). The table lives in a static scratch
    // buffer, so a whole-buffer sweep is bounded and total.
    if ctx.overflow {
        drain_mms(ctx.tslot);
        return Err(WordErr::WalkOverflow);
    }

    // Phase 2: exe resolution (may sleep; RCU is released).
    let mut i = 0usize;
    while i < ctx.ntasks {
        let (mm, has_sock, has_memfd) = {
            // Slot errors here are unreachable in practice, but an early
            // return must still drain the mms pinned by earlier iterations.
            let tasks = match slot_tasks(ctx.tslot) {
                Ok(b) => b,
                Err(_) => {
                    drain_mms(ctx.tslot);
                    return Err(WordErr::WalkOverflow);
                }
            };
            match tasks.get(i) {
                Some(r) => (r.mm, r.has_sock, r.has_memfd),
                None => {
                    drain_mms(ctx.tslot);
                    return Err(WordErr::WalkOverflow);
                }
            }
        };
        let mut exe_deleted = false;
        if !mm.is_null() {
            // SAFETY: mm pinned by get_task_mm; exe pointer read may race
            // an exec, but get_file_rcu validates via the file count.
            let exe = unsafe { core::ptr::addr_of!((*mm).__bindgen_anon_1.exe_file).read() };
            if !exe.is_null() {
                let mut tmp = exe;
                // SAFETY: brief RCU section, non-sleeping.
                let f = unsafe {
                    rust_helper_rcu_read_lock();
                    let got = kernel::bindings::get_file_rcu(&mut tmp);
                    rust_helper_rcu_read_unlock();
                    got
                };
                if !f.is_null() {
                    unsafe {
                        let dent: *mut dentry =
                            core::ptr::addr_of!((*f).__bindgen_anon_1.f_path.dentry).read();
                        if !dent.is_null() {
                            let dinode: *mut inode =
                                core::ptr::addr_of!((*dent).d_inode).read();
                            let nlink = if dinode.is_null() {
                                0
                            } else {
                                core::ptr::addr_of!((*dinode).__bindgen_anon_1.i_nlink).read()
                            };
                            // Deleted-but-open files always have nlink 0:
                            // exactly the ` (deleted)` readlink condition.
                            exe_deleted = nlink == 0;
                        }
                        kernel::bindings::fput(f);
                    }
                }
            }
            // SAFETY: our mm ref from phase 1.
            unsafe { kernel::bindings::mmput(mm) };
            let tasks = match slot_tasks(ctx.tslot) {
                Ok(b) => b,
                Err(_) => {
                    drain_mms(ctx.tslot);
                    return Err(WordErr::WalkOverflow);
                }
            };
            if let Some(r) = tasks.get_mut(i) {
                r.mm = core::ptr::null_mut();
                r.exe_deleted = exe_deleted;
                r.fileless = (exe_deleted || has_memfd) && has_sock;
            }
        }
        i = match i.checked_add(1) {
            Some(n) => n,
            // Unreachable (i < ntasks <= MAX_TASKS); drain before returning.
            None => {
                drain_mms(ctx.tslot);
                return Err(WordErr::WalkOverflow);
            }
        };
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Words.
// ---------------------------------------------------------------------------

type WordFunc = for<'s, 'd, 'o, 'p> fn(
    &'s mut [Val; MAX_STACK],
    &'d mut usize,
    &'o mut BufWriter<'p>,
    &'static str,
) -> Result<(), WordErr>;

struct Word {
    name: &'static str,
    func: WordFunc,
}

fn w_add(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    name: &'static str,
) -> Result<(), WordErr> {
    let b = pop(stack, depth)?;
    let a = pop(stack, depth)?;
    match (a, b) {
        (Val::Int(x), Val::Int(y)) => push(
            stack,
            depth,
            Val::Int(x.checked_add(y).ok_or(WordErr::IntOverflow)?),
        ),
        _ => Err(WordErr::Type(name)),
    }
}

fn w_sub(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    name: &'static str,
) -> Result<(), WordErr> {
    let b = pop(stack, depth)?;
    let a = pop(stack, depth)?;
    match (a, b) {
        (Val::Int(x), Val::Int(y)) => push(
            stack,
            depth,
            Val::Int(x.checked_sub(y).ok_or(WordErr::IntOverflow)?),
        ),
        _ => Err(WordErr::Type(name)),
    }
}

fn w_dup(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    // Resolve the free slot BEFORE popping: after the pop the value's own
    // slot reads as unreferenced, so a post-pop `free_slot` returns the
    // value's own slot and collection `dup` could never succeed.
    let top = match depth.checked_sub(1) {
        Some(t) => match stack.get(t) {
            Some(v) => *v,
            // Unreachable while the pop guard below holds; total, never traps.
            None => return Err(WordErr::Output),
        },
        None => return Err(WordErr::Underflow),
    };
    let nslot = match top {
        Val::Int(_) => 0,
        Val::Col { kind, .. } => free_slot(stack, *depth, kind)?,
    };
    let v = pop(stack, depth)?;
    match v {
        Val::Int(_) => {
            push(stack, depth, v)?;
            push(stack, depth, v)
        }
        Val::Col { kind, slot, n } => {
            // Copy into the free slot so the two values never alias.
            // (`nslot != slot` holds by construction -- `slot` was live when
            // `free_slot` ran; kept as a total guard.)
            if nslot == slot {
                return Err(WordErr::NoBuffer);
            }
            if n > MAX_UNIX {
                return Err(WordErr::Output);
            }
            let mut i = 0usize;
            while i < n {
                match kind {
                    // SAFETY: eval-exclusive buffers; one record at a time,
                    // never two borrows at once.
                    KIND_UNIX => unsafe {
                        let v = unix_get(slot, i)?;
                        unix_set(nslot, i, v)?;
                    },
                    KIND_TASKS => unsafe {
                        let v = tasks_get(slot, i)?;
                        tasks_set(nslot, i, v)?;
                    },
                    _ => unsafe {
                        let v = ints_get(slot, i)?;
                        ints_set(nslot, i, v)?;
                    },
                }
                i = i.checked_add(1).ok_or(WordErr::Output)?;
            }
            push(stack, depth, v)?;
            push(
                stack,
                depth,
                Val::Col {
                    kind,
                    slot: nslot,
                    n,
                },
            )
        }
    }
}

fn w_drop(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    pop(stack, depth)?;
    Ok(())
}

fn w_swap(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let a = pop(stack, depth)?;
    let b = pop(stack, depth)?;
    push(stack, depth, a)?;
    push(stack, depth, b)
}

/// ( a -- Int ) length of top (1 for scalars).
fn w_count(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let v = pop(stack, depth)?;
    push(stack, depth, Val::Int(v.len() as i64))
}

/// ( a -- ) pop top and PRINT it (classic Forth): the stack is empty after
/// and the sentence yield is the captured printed text. Scalars render as
/// `text <n>` (RULING Nov 2: `2 3 + .` yields `text 5`, not `int 5`).
/// Collections keep their typed rendering via `render_val`.
fn w_dot(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    match pop(stack, depth)? {
        Val::Int(n) => {
            let mut stage = [0u8; 32];
            let nbytes = {
                let mut w = BufWriter::new(&mut stage);
                w.append(b"text ").map_err(|_| WordErr::Output)?;
                w.append_i64(n).map_err(|_| WordErr::Output)?;
                w.append(b"\n").map_err(|_| WordErr::Output)?;
                w.finish()
            };
            emit_staged(out, &stage, nbytes)
        }
        v => render_val(out, v),
    }
}

/// ( -- ) render depth plus one tag per cell, stack untouched.
fn w_dots(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let mut stage = [0u8; 512];
    let nbytes = {
        let mut w = BufWriter::new(&mut stage);
        w.append(b"text <").map_err(|_| WordErr::Output)?;
        w.append_u64(*depth as u64).map_err(|_| WordErr::Output)?;
        w.append(b">").map_err(|_| WordErr::Output)?;
        let mut i = 0usize;
        while i < *depth {
            match stack.get(i) {
                Some(v) => {
                    w.append(b" ").map_err(|_| WordErr::Output)?;
                    w.append_str(v.tag()).map_err(|_| WordErr::Output)?;
                }
                None => return Err(WordErr::Output),
            }
            i = i.checked_add(1).ok_or(WordErr::Output)?;
        }
        w.append(b"\n").map_err(|_| WordErr::Output)?;
        w.finish()
    };
    emit_staged(out, &stage, nbytes)
}

/// Step-1 smoke word: proves the `text` output path end to end.
fn w_smoke(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    emit_text(out, "forth-step2-smoke")
}

/// ( -- Int ) total RAM bytes (`si_meminfo`: `totalram * mem_unit`).
fn w_mem(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let mut si: sysinfo = unsafe { core::mem::zeroed() };
    // SAFETY: plain output struct, sync call, may sleep (we are in process
    // context outside RCU here).
    unsafe { kernel::bindings::si_meminfo(&mut si) };
    let total = (si.totalram as u64)
        .checked_mul(si.mem_unit as u64)
        .ok_or(WordErr::IntOverflow)?;
    // totalram fits i64 on any real machine (u64->i64 could wrap past
    // 8 EiB); checked conversion keeps it total.
    let bytes = i64::try_from(total).map_err(|_| WordErr::IntOverflow)?;
    push(stack, depth, Val::Int(bytes))
}

/// ( -- Unix ) all unix sockets seen in one walk.
fn w_unix(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let uslot = free_slot(stack, *depth, KIND_UNIX)?;
    let tslot = free_slot(stack, *depth, KIND_TASKS)?;
    let mut ctx = WalkCtx {
        tslot,
        uslot,
        ntasks: 0,
        nunix: 0,
        cur: usize::MAX,
        overflow: false,
    };
    do_walk(&mut ctx)?;
    push(
        stack,
        depth,
        Val::Col {
            kind: KIND_UNIX,
            slot: uslot,
            n: ctx.nunix,
        },
    )
}

/// ( -- Tasks ) all thread-group leaders seen in one walk.
fn w_tasks(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let uslot = free_slot(stack, *depth, KIND_UNIX)?;
    let tslot = free_slot(stack, *depth, KIND_TASKS)?;
    let mut ctx = WalkCtx {
        tslot,
        uslot,
        ntasks: 0,
        nunix: 0,
        cur: usize::MAX,
        overflow: false,
    };
    do_walk(&mut ctx)?;
    push(
        stack,
        depth,
        Val::Col {
            kind: KIND_TASKS,
            slot: tslot,
            n: ctx.ntasks,
        },
    )
}

/// ( Unix -- Unix ) ownerless only.
fn w_orphans(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    name: &'static str,
) -> Result<(), WordErr> {
    match pop(stack, depth)? {
        Val::Col { kind: KIND_UNIX, slot, n } => {
            let buf = slot_unix(slot)?;
            let mut w = 0usize;
            let mut r = 0usize;
            while r < n {
                let keep = match buf.get(r) {
                    Some(rec) => rec.nowners == 0,
                    None => return Err(WordErr::Output),
                };
                if keep {
                    if w != r {
                        let rec = match buf.get(r) {
                            Some(v) => *v,
                            None => return Err(WordErr::Output),
                        };
                        match buf.get_mut(w) {
                            Some(d) => *d = rec,
                            None => return Err(WordErr::Output),
                        }
                    }
                    w = w.checked_add(1).ok_or(WordErr::Output)?;
                }
                r = r.checked_add(1).ok_or(WordErr::Output)?;
            }
            push(stack, depth, Val::Col { kind: KIND_UNIX, slot, n: w })
        }
        _ => Err(WordErr::Type(name)),
    }
}

/// ( Unix -- Ints ) peer inodes (absent/unresolvable dropped).
fn w_peers(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    name: &'static str,
) -> Result<(), WordErr> {
    match pop(stack, depth)? {
        Val::Col { kind: KIND_UNIX, slot, n } => {
            let islot = free_slot(stack, *depth, KIND_INTS)?;
            let mut out_n = 0usize;
            let mut r = 0usize;
            while r < n {
                // SAFETY: eval-exclusive buffers, indexed one at a time.
                let peer = unsafe { unix_get(slot, r)?.peer };
                if peer != 0 {
                    if out_n >= MAX_INTS {
                        return Err(WordErr::WalkOverflow);
                    }
                    match i64::try_from(peer) {
                        Ok(v) => unsafe {
                            ints_set(islot, out_n, v)?;
                            out_n = out_n.checked_add(1).ok_or(WordErr::Output)?;
                        },
                        Err(_) => {}
                    }
                }
                r = r.checked_add(1).ok_or(WordErr::Output)?;
            }
            push(
                stack,
                depth,
                Val::Col {
                    kind: KIND_INTS,
                    slot: islot,
                    n: out_n,
                },
            )
        }
        _ => Err(WordErr::Type(name)),
    }
}

/// ( Tasks -- Tasks ) fileless (deleted exe or memfd) AND socketed.
fn w_fileless(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    name: &'static str,
) -> Result<(), WordErr> {
    match pop(stack, depth)? {
        Val::Col { kind: KIND_TASKS, slot, n } => {
            let buf = slot_tasks(slot)?;
            let mut w = 0usize;
            let mut r = 0usize;
            while r < n {
                let keep = match buf.get(r) {
                    Some(rec) => rec.fileless,
                    None => return Err(WordErr::Output),
                };
                if keep {
                    if w != r {
                        let rec = match buf.get(r) {
                            Some(v) => *v,
                            None => return Err(WordErr::Output),
                        };
                        match buf.get_mut(w) {
                            Some(d) => *d = rec,
                            None => return Err(WordErr::Output),
                        }
                    }
                    w = w.checked_add(1).ok_or(WordErr::Output)?;
                }
                r = r.checked_add(1).ok_or(WordErr::Output)?;
            }
            push(stack, depth, Val::Col { kind: KIND_TASKS, slot, n: w })
        }
        _ => Err(WordErr::Type(name)),
    }
}

/// ( Tasks -- Ints ) pids.
fn w_pids(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    _out: &mut BufWriter<'_>,
    name: &'static str,
) -> Result<(), WordErr> {
    match pop(stack, depth)? {
        Val::Col { kind: KIND_TASKS, slot, n } => {
            let islot = free_slot(stack, *depth, KIND_INTS)?;
            let mut out_n = 0usize;
            let mut r = 0usize;
            while r < n {
                if out_n >= MAX_INTS {
                    return Err(WordErr::WalkOverflow);
                }
                // SAFETY: eval-exclusive buffers, indexed one at a time.
                let pid = unsafe { tasks_get(slot, r)?.pid };
                unsafe { ints_set(islot, out_n, pid as i64)? };
                out_n = out_n.checked_add(1).ok_or(WordErr::Output)?;
                r = r.checked_add(1).ok_or(WordErr::Output)?;
            }
            push(
                stack,
                depth,
                Val::Col {
                    kind: KIND_INTS,
                    slot: islot,
                    n: out_n,
                },
            )
        }
        _ => Err(WordErr::Type(name)),
    }
}

/// Print `text <name> 0x<hex>` (the disarmed cursed-word shape, and the
/// kprobe-resolve diagnostic shape). Same no-`core::fmt` hex as `w_do_exit`.
fn print_addr(out: &mut BufWriter<'_>, name: &str, addr: usize) -> Result<(), WordErr> {
    let mut stage = [0u8; 96];
    let nbytes = {
        let mut w = BufWriter::new(&mut stage);
        w.append(b"text ").map_err(|_| WordErr::Output)?;
        w.append_str(name).map_err(|_| WordErr::Output)?;
        w.append(b" 0x").map_err(|_| WordErr::Output)?;
        w.append_u64_hex(addr as u64).map_err(|_| WordErr::Output)?;
        w.append(b"\n").map_err(|_| WordErr::Output)?;
        w.finish()
    };
    emit_staged(out, &stage, nbytes)
}

/// Ask the kernel for a symbol's address via a kprobe, then disarm it.
///
/// Narration rule (Wes, confirmed 2026-11-02): this is "we ask the kernel
/// for the address via a kprobe, then disarm it." NEVER "we iterate
/// kallsyms" — `kallsyms_on_each_symbol` is unexported on this kernel and
/// that route is retired. `register_kprobe` resolves the name through the
/// kernel-internal kallsyms lookup; we copy `kp.addr` and unregister
/// immediately (minimal int3 window, never leave the probe armed).
///
/// Returns the runtime (KASLR'd) address, or `Kprobe` / `Resolve`.
fn kprobe_resolve(name: &[u8]) -> Result<usize, WordErr> {
    // Callers pass `b"...\0"` literals: NUL-terminated, 'static. A missing
    // NUL would let the kernel strcmp run off the name; do not debug_assert
    // (this module's no-panic discipline forbids pulling panic machinery).
    let mut kp: KProbe = unsafe { core::mem::zeroed() };
    kp.symbol_name = name.as_ptr();
    kp.pre_handler = Some(kprobe_nop);
    // SAFETY: `kp` is a full `KProbe` (512 B tail covers opcode + ainsn +
    // flags on this arch/config); we are in process context, no RCU held;
    // the probe is unregistered before this function returns.
    let rc = unsafe { register_kprobe(&mut kp) };
    if rc != 0 {
        return Err(WordErr::Kprobe);
    }
    let addr = kp.addr as usize;
    // SAFETY: same `kp`, registered above, never left armed.
    unsafe { unregister_kprobe(&mut kp) };
    if addr == 0 {
        return Err(WordErr::Kprobe);
    }
    Ok(addr)
}

/// Resolve an arbitrary symbol by first kprobe-resolving
/// `kallsyms_lookup_name` (a real exported-text function, so the kprobe
/// lands), then calling it. This is the only route to data symbols
/// (`slab_caches` is an OBJECT, not a function — a direct kprobe on it may
/// fail the kernel-text check depending on section typing).
fn ksym(name: &[u8]) -> Result<usize, WordErr> {
    let kln_addr = kprobe_resolve(b"kallsyms_lookup_name\0")?;
    // SAFETY: the address came from the kernel's own resolver; the callee
    // is the real `unsigned long kallsyms_lookup_name(const char *)`.
    let kln: unsafe extern "C" fn(*const u8) -> usize =
        unsafe { core::mem::transmute(kln_addr) };
    // SAFETY: `name` is NUL-terminated and lives for the call.
    let a = unsafe { kln(name.as_ptr()) };
    if a == 0 {
        return Err(WordErr::Resolve);
    }
    Ok(a)
}

// -- safety toggle ----------------------------------------------------------

/// ( -- ) arm the cursed words. Easy to flip, as ruled; still root-only.
fn w_arm(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    CURSED_ARMED.store(true, Ordering::Relaxed);
    pr_info!("forth: cursed words ARMED\n");
    emit_text(out, "cursed ARMED")
}

/// ( -- ) back to address-only.
fn w_disarm(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    CURSED_ARMED.store(false, Ordering::Relaxed);
    pr_info!("forth: cursed words DISARMED\n");
    emit_text(out, "cursed DISARMED")
}

/// ( -- ) query the toggle.
fn w_armed_q(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    if CURSED_ARMED.load(Ordering::Relaxed) {
        emit_text(out, "cursed ARMED")
    } else {
        emit_text(out, "cursed DISARMED")
    }
}

// -- cursed dictionary (all three families; casting is Wes's final pass) -----

/// `do_exit`: address-only, or — only when armed — actually call it (the
/// write(2) task ends; the sentence never completes).
fn w_do_exit(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let f: unsafe extern "C" fn(core::ffi::c_long) -> ! = do_exit;
    let addr = f as usize;
    if CURSED_ARMED.load(Ordering::Relaxed) {
        // SAFETY: armed by explicit `arm` on the 0600 node. Never returns.
        unsafe { do_exit(0) };
    }
    print_addr(out, "do_exit", addr)
}

/// `panic`: address-only, or — only when armed — actually call it (never
/// returns; the guest/host dies). Same five-line pattern as `do_exit`.
fn w_panic(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    // This tree's bindgen types `c_char` as `u8` (see the generated decl).
    let f: unsafe extern "C" fn(*const u8, ...) -> ! = kernel::bindings::panic;
    let addr = f as usize;
    if CURSED_ARMED.load(Ordering::Relaxed) {
        // SAFETY: armed by explicit `arm`. Never returns.
        unsafe { kernel::bindings::panic(b"forth: cursed word panic invoked\0".as_ptr()) };
    }
    print_addr(out, "panic", addr)
}

/// `emergency_restart`: address-only, or — only when armed — actually call
/// it (never returns; the machine reboots).
fn w_emergency_restart(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let f: unsafe extern "C" fn() -> ! = emergency_restart;
    let addr = f as usize;
    if CURSED_ARMED.load(Ordering::Relaxed) {
        // SAFETY: armed by explicit `arm`. Never returns.
        unsafe { emergency_restart() };
    }
    print_addr(out, "emergency_restart", addr)
}

/// `kernel_restart`: address-only, or — only when armed — actually call it
/// with a NULL command (never returns).
fn w_kernel_restart(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let f: unsafe extern "C" fn(*mut u8) -> ! = kernel_restart;
    let addr = f as usize;
    if CURSED_ARMED.load(Ordering::Relaxed) {
        // SAFETY: armed by explicit `arm`. NULL cmd = default restart.
        // Never returns.
        unsafe { kernel_restart(core::ptr::null_mut()) };
    }
    print_addr(out, "kernel_restart", addr)
}

/// `orderly_poweroff`: address-only, or — only when armed — actually call
/// it. NOTE: this one RETURNS (it schedules a workqueue); the machine
/// powers off shortly after, the sentence itself completes.
fn w_orderly_poweroff(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let f: unsafe extern "C" fn(bool) = orderly_poweroff;
    let addr = f as usize;
    if CURSED_ARMED.load(Ordering::Relaxed) {
        // SAFETY: armed by explicit `arm`. Returns after scheduling.
        unsafe { orderly_poweroff(true) };
        return emit_text(out, "orderly_poweroff scheduled");
    }
    print_addr(out, "orderly_poweroff", addr)
}

// -- kprobe / slabs spike (go/no-go tonight, Wes push mode) -----------------

/// ( -- ) print the kprobe-resolved address of `kallsyms_lookup_name`.
/// The "ask the kernel, then disarm" word, made visible.
fn w_ksyms(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let addr = kprobe_resolve(b"kallsyms_lookup_name\0")?;
    print_addr(out, "kallsyms_lookup_name", addr)
}

/// ( -- ) print the resolved address of `slab_caches` (the unexported
/// list_head). Spike half-one: can we even name the address?
fn w_slab_caches(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let addr = ksym(b"slab_caches\0")?;
    print_addr(out, "slab_caches", addr)
}

/// ( -- ) slabs spike: resolve `slab_caches`, walk the list, emit
/// `text <name> <object_size>` per cache (cap 64). Diagnostic print word
/// (do_exit family), not a push word — the spike's job is to be read.
///
/// No slab_mutex take: the guest fixture is quiet, and locking a
/// kprobe-resolved mutex is the next step only if the walk itself is GO.
/// A bad `next` pointer (not kernel-virtual, or not advancing) fails the
/// eval rather than deref'ing garbage.
fn w_slabs(
    _stack: &mut [Val; MAX_STACK],
    _depth: &mut usize,
    out: &mut BufWriter<'_>,
    _name: &'static str,
) -> Result<(), WordErr> {
    let head_addr = ksym(b"slab_caches\0")?;
    let head = head_addr as *mut list_head;
    // SAFETY: `head` is the kernel's own list_head; reading `next` is a
    // plain load. We do not write it.
    let mut cur = unsafe { (*head).next };
    let mut n = 0usize;
    while cur != head && n < 64 {
        let cur_addr = cur as usize;
        if cur_addr < KERN_ADDR_MIN {
            // Insane link: stop, keep what we have, report the walk.
            break;
        }
        let cache = cur_addr.wrapping_sub(KMEM_CACHE_LIST_OFF) as usize;
        if cache < KERN_ADDR_MIN {
            break;
        }
        // SAFETY: cache is a plausible kmem_cache (list member pointed at
        // us from the official list). Offsets are BTF-pinned (see consts).
        let name_p = unsafe { *((cache + KMEM_CACHE_NAME_OFF) as *const *const u8) };
        let objsize = unsafe { *((cache + KMEM_CACHE_SIZE_OFF) as *const u32) };
        out.append(b"text ").map_err(|_| WordErr::Output)?;
        if (name_p as usize) < KERN_ADDR_MIN {
            out.append(b"?").map_err(|_| WordErr::Output)?;
        } else {
            // SAFETY: name_p is a plausible kernel pointer; bounded read
            // to 48 bytes, stop at NUL. Non-printable -> `?`.
            let mut i = 0usize;
            while i < 48 {
                let b = unsafe { *name_p.add(i) };
                if b == 0 {
                    break;
                }
                if (0x20..0x7f).contains(&b) {
                    out.append(&[b]).map_err(|_| WordErr::Output)?;
                } else {
                    out.append(b"?").map_err(|_| WordErr::Output)?;
                }
                i = i.checked_add(1).ok_or(WordErr::Output)?;
            }
        }
        out.append(b" ").map_err(|_| WordErr::Output)?;
        out.append_u64(objsize as u64).map_err(|_| WordErr::Output)?;
        out.append(b"\n").map_err(|_| WordErr::Output)?;
        let next = unsafe { (*cur).next };
        // Refuse a self-loop that isn't the list head (corrupt).
        if next == cur && head != cur {
            break;
        }
        cur = next;
        n = n.checked_add(1).ok_or(WordErr::Output)?;
    }
    Ok(())
}

/// Step-2 dictionary; linear scan is plenty for these words.
///
/// Push-vs-print rule (all future words must follow it): words compute on the
/// stack and never emit; only the boundary render (leftover stack) and `text`
/// diagnostics emit. Sole exception: `.` on collections keeps typed rendering
/// via `render_val` (documented, not text-ified).
/// Cursed words, `arm`/`disarm`/`armed?`, `ksyms`, `slab-caches` and `slabs`
/// are the do_exit family: they PRINT (address / state / spike dump) and
/// leave the stack empty. Documented deviation, same as `do_exit`.
const WORDS: &[Word] = &[
    Word { name: "+", func: w_add },
    Word { name: "-", func: w_sub },
    Word { name: "dup", func: w_dup },
    Word { name: "drop", func: w_drop },
    Word { name: "swap", func: w_swap },
    Word { name: "count", func: w_count },
    Word { name: ".", func: w_dot },
    Word { name: ".s", func: w_dots },
    Word { name: "smoke", func: w_smoke },
    Word { name: "do_exit", func: w_do_exit },
    Word { name: "panic", func: w_panic },
    Word { name: "emergency_restart", func: w_emergency_restart },
    Word { name: "kernel_restart", func: w_kernel_restart },
    Word { name: "orderly_poweroff", func: w_orderly_poweroff },
    Word { name: "arm", func: w_arm },
    Word { name: "disarm", func: w_disarm },
    Word { name: "armed?", func: w_armed_q },
    Word { name: "ksyms", func: w_ksyms },
    Word { name: "slab-caches", func: w_slab_caches },
    Word { name: "slabs", func: w_slabs },
    Word { name: "unix", func: w_unix },
    Word { name: "tasks", func: w_tasks },
    Word { name: "orphans", func: w_orphans },
    Word { name: "peers", func: w_peers },
    Word { name: "fileless", func: w_fileless },
    Word { name: "pids", func: w_pids },
    Word { name: "mem", func: w_mem },
];

/// Read the `cursed` module parameter (0 hides, nonzero shows).
///
/// This snapshot's kernel crate exposes no value-reader on
/// `ModuleParamAccess` (no `read`/`get`, no `Deref` — verified by probe
/// builds against the pinned rmeta; the `module!` doc example's `.read()`
/// does not exist here), so read the live byte through the same pointer the
/// C param ops use (`as_void_ptr`, called by the macro's own expansion).
/// Sound: single aligned byte; `perm` is fixed 0 (no sysfs store path can
/// race us — the insmod-time parse completes before `init` runs).
/// Layout of `ModuleParamAccess<u8>` in this pinned tree (12 bytes).
///
/// Verified against the built artifact AND the live guest (not assumed).
/// `objdump -s -j .data forth.ko` shows the `cursed` static as
/// `00*8 01 00 00 00`: `ModuleParamAccess::new(1)` plants the default at +8
/// while `as_void_ptr` yields the struct base. Guest oracle (rmmod +
/// re-insmod with different values, `cursed-dbg` word dumping all 12 bytes):
///
/// | insmod args      | +0 | +4 | +8 |
/// |------------------|----|----|----|
/// | (none, default)  | 0  | 0  | 1  |
/// | `cursed=5`       | 2  | 5  | 1  |
/// | `cursed=0`       | 2  | 0  | 1  |
/// | `cursed=2`       | 2  | 2  | 1  |
///
/// So +4 is the live parsed value (tracks the argument), +8 is the
/// `new()` default (never touched by the parse path), and +0 is a
/// set-flag (0 iff no explicit param was passed). This snapshot's kernel
/// crate exposes no value-reader on `ModuleParamAccess` (no `read`/`get`,
/// no `Deref` — verified by probe builds against the pinned rmeta; the
/// `module!` doc example's `.read()` does not exist here), so the gate
/// below merges the three cells with the documented spec semantics: an
/// explicit value wins, otherwise the default applies.
const CURSED_SET_OFF: usize = 0;
const CURSED_LIVE_OFF: usize = 4;
const CURSED_DEFAULT_OFF: usize = 8;

fn cursed_on() -> bool {
    // SAFETY: `as_void_ptr` points at the 12-byte `cursed` static owned by
    // this module for its whole lifetime; all three offsets are in-bounds
    // aligned single-byte reads. `perm` is fixed 0 (no sysfs store path can
    // race us — the insmod-time parse precedes `init`).
    unsafe {
        let base = module_parameters::cursed.as_void_ptr() as *const u8;
        let was_set = base.wrapping_add(CURSED_SET_OFF).read() != 0;
        let live = base.wrapping_add(CURSED_LIVE_OFF).read();
        let default = base.wrapping_add(CURSED_DEFAULT_OFF).read();
        if was_set {
            live != 0
        } else {
            default != 0
        }
    }
}

fn lookup(name: &str) -> Option<(WordFunc, &'static str)> {
    // `cursed` module parameter gate (OTP-N): with `cursed=0` the cursed
    // words are absent from the dictionary — the sentence fails exactly like
    // a typo (`err undefined word: panic`). Default (`cursed=1`) keeps them.
    if !cursed_on() {
        match name {
            "panic" | "emergency_restart" => return None,
            _ => {}
        }
    }
    for w in WORDS {
        if w.name == name {
            return Some((w.func, w.name));
        }
    }
    None
}

enum EvalErr<'t> {
    Word(WordErr),
    Undefined(&'t str),
}

impl<'e> From<WordErr> for EvalErr<'e> {
    fn from(e: WordErr) -> Self {
        EvalErr::Word(e)
    }
}

/// Hand-rolled `i64` literal parser. `str::parse::<i64>` monomorphizes
/// `from_str_radix` (with overflow-checked arithmetic) into this object,
/// which pulls `panic_const_*_overflow` refs; the checked ops below lower
/// to branches and never trap. Returns `None` exactly when `parse` fails
/// (empty, non-digits, overflow), so stage-typo behavior is unchanged.
fn parse_i64(tok: &str) -> Option<i64> {
    let bytes = tok.as_bytes();
    let first = bytes.first()?;
    let (neg, digits) = match first {
        b'+' => (false, bytes.get(1..)?),
        b'-' => (true, bytes.get(1..)?),
        _ => (false, bytes),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: u64 = 0;
    for d in digits.iter() {
        let dig = d.checked_sub(b'0')?;
        if dig > 9 {
            return None;
        }
        v = v.checked_mul(10)?.checked_add(dig as u64)?;
    }
    if neg {
        // `v == i64::MAX+1` wraps to `i64::MIN`, the correct value.
        if v > (i64::MAX as u64).wrapping_add(1) {
            return None;
        }
        Some((v as i64).wrapping_neg())
    } else {
        if v > i64::MAX as u64 {
            return None;
        }
        Some(v as i64)
    }
}

/// ASCII whitespace test for the byte tokenizer below.
fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c)
}

fn run_tokens<'t>(
    stack: &mut [Val; MAX_STACK],
    depth: &mut usize,
    out: &mut BufWriter<'_>,
    input: &'t str,
) -> Result<(), EvalErr<'t>> {
    // Byte tokenizer, not `split_whitespace`: the latter monomorphizes
    // `CharIndices::next` (byte-index `+`) into this object, which pulls
    // `panic_const_add_overflow`. ASCII-only split (documented deviation:
    // Unicode whitespace inside a token is kept as token bytes; the parity
    // sentences use plain spaces). Boundaries always fall on char
    // boundaries (no multi-byte UTF-8 sequence contains an ASCII-whitespace
    // byte), so per-token `from_utf8` cannot fail.
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        while i < bytes.len() {
            match bytes.get(i) {
                Some(b) if is_ws(*b) => {
                    i = i.checked_add(1).ok_or(WordErr::Output)?;
                }
                Some(_) => break,
                None => break,
            }
        }
        if i >= bytes.len() {
            break;
        }
        let start = i;
        while i < bytes.len() {
            match bytes.get(i) {
                Some(b) if !is_ws(*b) => {
                    i = i.checked_add(1).ok_or(WordErr::Output)?;
                }
                _ => break,
            }
        }
        let tok_bytes = match bytes.get(start..i) {
            Some(b) => b,
            None => return Err(WordErr::Output.into()),
        };
        let tok = match core::str::from_utf8(tok_bytes) {
            Ok(t) => t,
            // Unreachable (see above); total instead of trapping.
            Err(_) => return Err(WordErr::Output.into()),
        };
        if let Some(n) = parse_i64(tok) {
            push(stack, depth, Val::Int(n))?;
        } else if let Some((word, name)) = lookup(tok) {
            word(stack, depth, out, name)?;
        } else {
            return Err(EvalErr::Undefined(tok));
        }
    }
    Ok(())
}

/// Evaluate one line into `inner`, storing either value lines plus `ok` or a
/// single `err` line. Partial output from a failed eval is discarded.
fn eval_line(inner: &mut Inner, input: &str) {
    let mut w = BufWriter::new(&mut inner.out);
    let mut stack = [Val::Int(0); MAX_STACK];
    let mut depth = 0usize;
    match run_tokens(&mut stack, &mut depth, &mut w, input) {
        Ok(()) => {
            let mut failed = false;
            let mut i = 0usize;
            while i < depth {
                match stack.get(i) {
                    Some(v) => {
                        if render_val(&mut w, *v).is_err() {
                            failed = true;
                            break;
                        }
                    }
                    None => {
                        failed = true;
                        break;
                    }
                }
                match i.checked_add(1) {
                    Some(n) => i = n,
                    None => {
                        failed = true;
                        break;
                    }
                }
            }
            if failed {
                emit_err(&mut w, b"err output too large", b"");
            } else if w.append(b"ok\n").is_err() {
                emit_err(&mut w, b"err output too large", b"");
            }
        }
        Err(EvalErr::Word(e)) => match e {
            WordErr::Type(word) => {
                emit_err(&mut w, b"err type error in ", word.as_bytes());
            }
            _ => {
                emit_err(&mut w, b"err ", e.msg().as_bytes());
            }
        },
        Err(EvalErr::Undefined(tok)) => {
            emit_err(&mut w, b"err undefined word: ", tok.as_bytes());
        }
    }
    inner.out_len = w.finish();
    inner.has_output = true;
}

// ---------------------------------------------------------------------------
// Raw file_operations transport.
// ---------------------------------------------------------------------------

/// NOTE: callbacks return literal negative errnos (`-7`/`-14`/`-16`) at
/// each site instead of mapping `Error`, so the errno stays greppable where
/// it is produced.

fn inner_of(file: *mut file) -> Result<&'static Mutex<Inner>, isize> {
    // SAFETY: debugfs set private_data from our `data` arg at creation;
    // the Forth struct (owning the Mutex) outlives the file (removed in
    // Drop before fields drop).
    unsafe {
        if file.is_null() {
            return Err(-14);
        }
        let p = core::ptr::addr_of!((*file).private_data).read() as *mut Mutex<Inner>;
        if p.is_null() {
            return Err(-14);
        }
        Ok(&*p)
    }
}

/// Open path: propagate the debugfs `data` pointer (`inode->i_private`)
/// into `file->private_data`. debugfs's full proxy does NOT do this when
/// the fops has no `.open` (OTP-V probe: `file->private_data` arrives NULL
/// → every read/write fails `-EFAULT`). Standard `simple_open` pattern,
/// spelled out (no `simple_open` binding is declared).
unsafe extern "C" fn repl_open(inode: *mut inode, file: *mut file) -> c_int {
    // SAFETY: VFS open callback contract; inode/file live for the call.
    unsafe {
        if inode.is_null() || file.is_null() {
            return -22;
        }
        let data = core::ptr::addr_of!((*inode).i_private).read();
        core::ptr::addr_of_mut!((*file).private_data).write(data);
        0
    }
}

/// Read path: emit the stored response with `*ppos` tracking. Blocks in
/// `lock()` while a write-side eval holds the mutex, so bytes are always
/// one complete response.
unsafe extern "C" fn repl_read(
    file: *mut file,
    buf: *mut u8,
    len: usize,
    ppos: *mut kernel::bindings::loff_t,
) -> isize {
    // SAFETY: VFS read callback contract; user buffer via UserSlice.
    unsafe {
        if ppos.is_null() {
            return -22;
        }
        let start = core::ptr::addr_of!(*ppos).read();
        if start != 0 {
            return 0;
        }
        let inner = match inner_of(file) {
            Ok(m) => m,
            Err(r) => return r,
        };
        let guard = inner.lock();
        if !guard.has_output || guard.out_len == 0 {
            return 0;
        }
        let avail = match guard.out_len.checked_sub(start as usize) {
            Some(a) => a,
            None => return 0,
        };
        let n = core::cmp::min(avail, len);
        let src = match guard.out.get(..guard.out_len) {
            Some(b) => b,
            None => return -14,
        };
        let chunk = match src.get(..n) {
            Some(c) => c,
            None => return -14,
        };
        let us = UserSlice::new(UserPtr::from_ptr(buf as *mut c_void), len);
        let mut writer = us.writer();
        if writer.write_slice(chunk).is_err() {
            return -14;
        }
        core::ptr::addr_of_mut!(*ppos).write(n as kernel::bindings::loff_t);
        n as isize
    }
}

/// Write path: one line, at most `MAX_LINE` bytes, evaluated synchronously.
/// Only one eval runs at a time (`try_lock` fails with `-EBUSY` otherwise).
unsafe extern "C" fn repl_write(
    file: *mut file,
    buf: *const u8,
    len: usize,
    _ppos: *mut kernel::bindings::loff_t,
) -> isize {
    // SAFETY: VFS write callback contract; user buffer via UserSlice.
    // (No raw derefs here: `inner_of` encapsulates the only one.)
    // Over-long writes fail with `-E2BIG` and never eval. Clear any stale
    // response first so the next read sees EOF instead of replaying the
    // previous sentence's output (`try_lock`: never sleep a failing write;
    // if an eval holds the mutex it will overwrite the buffer anyway).
    if len > MAX_LINE {
        if let Ok(inner) = inner_of(file) {
            if let Some(mut guard) = inner.try_lock() {
                guard.has_output = false;
                guard.out_len = 0;
            }
        }
        return -7;
    }
    let inner = match inner_of(file) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let mut guard = match inner.try_lock() {
        Some(g) => g,
        None => return -16,
    };
    let mut input = [0u8; MAX_LINE];
    let dst = match input.get_mut(..len) {
        Some(s) => s,
        None => return -14,
    };
    let us = UserSlice::new(UserPtr::from_ptr(buf as *mut c_void), len);
    let mut reader = us.reader();
    if reader.read_slice(dst).is_err() {
        return -14;
    }
    let mut elen = len;
    if elen > 0 && input.get(elen - 1) == Some(&b'\n') {
        elen -= 1;
    }
    if elen > 0 && input.get(elen - 1) == Some(&b'\r') {
        elen -= 1;
    }
    let bytes = match input.get(..elen) {
        Some(b) => b,
        None => return -14,
    };
    match core::str::from_utf8(bytes) {
        Ok(text) => eval_line(&mut guard, text),
        Err(_) => {
            let mut w = BufWriter::new(&mut guard.out);
            emit_err(&mut w, b"err invalid utf-8", b"");
            guard.out_len = w.finish();
            guard.has_output = true;
        }
    }
    len as isize
}

/// ERR_PTR test for debugfs constructors.
fn is_err_ptr(p: *mut c_void) -> bool {
    (p as usize) >= usize::MAX.wrapping_sub(4095)
}

/// Module-lifetime file operations. `static` (not a struct field) because
/// debugfs keeps the `fops` pointer: it must never move. Constructed in
/// `const` context so no runtime init ordering is involved.
const fn make_fops() -> file_operations {
    let mut f: file_operations = unsafe { core::mem::zeroed() };
    // Pin the module while the repl is open: VFS takes a module ref on open,
    // so `rmmod` with a held-open repl fails `EBUSY` instead of freeing code
    // under in-flight syscalls. (Owner was null before: rmmod-mid-read was a
    // UAF, mitigated only by the close-before-rmmod demo rule.)
    f.owner = unsafe { core::ptr::addr_of_mut!(kernel::bindings::__this_module) };
    f.open = Some(repl_open);
    f.read = Some(repl_read);
    f.write = Some(repl_write);
    f
}

static mut FOPS: file_operations = make_fops();

struct Forth {
    inner: Pin<KBox<Mutex<Inner>>>,
    dir: *mut dentry,
    file: *mut dentry,
}

// SAFETY: `Forth` only crosses threads at module load/unload (serialized by
// the module mutex); the raw dentries are touched in `init`/`Drop` only.
unsafe impl Send for Forth {}
unsafe impl Sync for Forth {}

impl kernel::Module for Forth {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("forth: Step 2 init\n");
        let mut inner = KBox::pin_init(
            Mutex::new(
                Inner {
                    out: [0; OUT_MAX],
                    out_len: 0,
                    has_output: false,
                },
                c_str!("forth repl lock"),
                static_lock_class!(),
            ),
            GFP_KERNEL,
        )?;
        // SAFETY: pinned box is never moved out; only the address and
        // `Mutex` methods (which do not move) are used.
        let inner_ptr =
            unsafe { inner.as_mut().get_unchecked_mut() as *mut Mutex<Inner> as *mut c_void };
        // SAFETY: debugfs constructors, sync, may sleep (process context).
        let dir = unsafe { kernel::bindings::debugfs_create_dir(c_str!("forth").as_ptr() as *const u8, core::ptr::null_mut()) };
        if dir.is_null() || is_err_ptr(dir as *mut c_void) {
            pr_info!("forth: debugfs_create_dir failed\n");
            return Err(ENOMEM);
        }
        let file = unsafe {
            kernel::bindings::debugfs_create_file_full(
                c_str!("repl").as_ptr() as *const u8,
                0o600 as umode_t,
                dir,
                inner_ptr,
                core::ptr::null(),
                &raw const FOPS as *const file_operations,
            )
        };
        if file.is_null() || is_err_ptr(file as *mut c_void) {
            pr_info!("forth: debugfs_create_file_full failed\n");
            unsafe { kernel::bindings::debugfs_remove(dir) };
            return Err(ENOMEM);
        }
        // The fops pointer stored by debugfs points at the module-lifetime
        // `static FOPS`, which never moves. `fops.owner` is `THIS_MODULE`, so
        // rmmod with the repl open fails `EBUSY` (close-before-rmmod is still
        // the demo rule, now enforced by VFS instead of honor).
        pr_info!("forth: /sys/kernel/debug/forth/repl ready (0600)\n");
        Ok(Forth { inner, dir, file })
    }
}

impl Drop for Forth {
    fn drop(&mut self) {
        // SAFETY: files removed before fields drop, so private_data never
        // dangles; no eval can be in flight after the file is gone (an
        // in-flight write holds the mutex but not the file; it completes
        // against live memory, then the KBox drops).
        unsafe {
            kernel::bindings::debugfs_remove(self.file);
            kernel::bindings::debugfs_remove(self.dir);
        }
        let n = self.inner.lock().out_len;
        pr_info!("forth: exit, last response {} bytes\n", n);
    }
}

module! {
    type: Forth,
    name: "forth",
    authors: ["rustforth contributors"],
    description: "In-kernel Forth Step 2: walk words + hardening",
    license: "GPL",
    // OTP-N: second safety layer (Wes order, Nov 3). With `cursed=0` on the
    // insmod line, `panic` and `emergency_restart` are absent from the
    // dictionary (`lookup` returns None → `err undefined word`). Default 1
    // keeps current stage behavior. Orthogonal to `CURSED_ARMED` (runtime
    // call-vs-print toggle). NOTE: this tree's `params` supports int types
    // only (no bool), so `cursed` is a `u8` with boolean semantics.
    params: {
        cursed: u8 {
            default: 1,
            description: "Expose cursed words panic/emergency_restart (0 hides them from the dict)",
        },
    },
}
