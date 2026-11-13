# forth0

A Forth REPL in the Linux kernel. A Rust-for-Linux module that puts an interactive Forth interpreter in ring 0. Write a sentence, read the kernel back.

```
> unix
unix 304 - 58 305
ok
> tasks fileless
task 60 busybox 0
ok
> do_exit
text do_exit 0xffffffffac05b050
ok
```

## Layout

- `src/`: the module. `forth.rs`, a no_std Forth core, plus a Makefile. Build with `make -C $KDIR M=$PWD modules` against configured kernel source with Rust support (`CONFIG_RUST=y`, matching `rustc`; see your kernel's `CONFIG_RUSTC_VERSION`).
- `driver/`: a zero-dependency userspace client. A REPL, `--eval` batch mode, a `--mock` responder, and a `--self-test` conformance suite.
- `scripts/`: `demo.sh` (one-command guest proof), `interact.sh` (interactive guest shell), `record.sh` (about 30 seconds to re-film everything). Set `RFORTH_WORK` to move the staging dir (default `/dev/shm/...`).
- `captures/`: stills from real KVM guests.

## Status

Research demo, not a product. The module taints your kernel, needs root, and you should not ship it. Read-only by design (no `!` word). The one unsafe thing it does on purpose is take addresses of exported symbols (`do_exit`, `panic`) and print them.

## License

GPL-2.0.
