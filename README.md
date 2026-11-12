# rustforth (placeholder name) — a Forth REPL in the Linux kernel

A Rust-for-Linux module that puts an interactive Forth interpreter in
ring 0. Write a sentence, read the kernel back. Built for a 5-minute
lightning talk; kept honest by its own test harness.

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

Talk: "What If the Kernel Spoke Forth?" (Ubuntu Summit lightning).
Thesis: *stop querying your kernel — talk to it.*

## Layout

- `src/` — the module (`forth.rs`, no_std Forth core; `Makefile`).
  Build: `make -C $KDIR M=$PWD modules` against your kernel's
  configured source with Rust support (`CONFIG_RUST=y`, matching
  `rustc` — see your kernel's `CONFIG_RUSTC_VERSION`).
- `driver/` — zero-dep userspace client: REPL, `--eval` batch mode,
  `--mock` responder, `--self-test` conformance suite.
- `scripts/` — `demo.sh` (one-command guest proof), `interact.sh`
  (interactive guest shell), `record.sh` (~30s full re-film).
  Set `RFORTH_WORK` to move the staging dir (default `/dev/shm/...`).
- `captures/` — stills from real KVM guests.

## Status

Research demo, not a product. The module taints your kernel, needs
root, and you should not ship it. Read-only by design (no `!` word);
the one unsafe thing it does on purpose is take addresses of exported
symbols (`do_exit`, `panic`) and print them — never call them.

## License

GPL-2.0. Same license as the thing it lives in.
