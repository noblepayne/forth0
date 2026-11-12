//! `--mock` responder: implements line-protocol v0.1 byte-for-byte.
//!
//! The mock owns one end of a socketpair; the client writes one line and
//! reads to the sentinel, exactly like the debugfs repl. Canned responses
//! cover the demo sentences; anything else fails the way the kernel does
//! (`err undefined word: <first-token>`), never hangs.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

/// Live MemTotal (bytes) as the canned `mem` answer, so `mem` stays
/// realistic. Falls back to a constant if /proc is unreadable.
pub fn mem_bytes() -> u64 {
    for line in std::fs::read_to_string("/proc/meminfo").unwrap_or_default().lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            if let Some(kb) = rest.split_whitespace().next().and_then(|n| n.parse::<u64>().ok()) {
                return kb.saturating_mul(1024);
            }
        }
    }
    16_777_216_000
}

/// Canned full response (value lines + sentinel, `\n`-terminated) for one
/// request line. Pure function — this is what the conformance test pins.
pub fn respond(line: &str) -> String {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.len() > crate::proto::MAX_LINE {
        // NOTE: the kernel has no in-band string for this case (over-long
        // writes fail with errno -E2BIG and never eval, so the socketpair
        // double cannot carry an errno); `err line too long` is the
        // mock-only mirror of that errno, distinct from the kernel's
        // `err output too large` (OUT_MAX overflow mid-eval).
        return "err line too long\n".to_string();
    }
    match line {
        // RULING (Wes, Nov 2): `.` pops+prints, stack empty, yield is the
        // captured printed text — `2 3 + .` renders `text 5`, not `int 5`.
        "2 3 + ." => "text 5\nok\n".to_string(),
        // Spec example: orphan peer inodes.
        "unix orphans peers" => "ints 18412 18586\nok\n".to_string(),
        "tasks fileless count" => "int 1\nok\n".to_string(),
        "tasks fileless pids" => "ints 4242\nok\n".to_string(),
        "1 2 3" => "int 1\nint 2\nint 3\nok\n".to_string(),
        "mem" => format!("int {}\nok\n", mem_bytes()),
        // RULING (Wes, Nov 2): `do_exit` prints by design, never calls it:
        // the kernel emits `text do_exit 0x<real-addr>` + `ok` (address varies
        // per boot); the mock pins a fixed sentinel addr for determinism.
        "do_exit" => "text do_exit 0xffffffffa1b2c3d4\nok\n".to_string(),
        "" => "ok\n".to_string(),
        // Spec example: a typo renders cleanly, never hangs.
        "frobnicate" => "err undefined word: frobnicate\n".to_string(),
        other => {
            let tok = other.split_whitespace().next().unwrap_or(other);
            format!("err undefined word: {tok}\n")
        }
    }
}

/// Serve one client connection until EOF. One eval at a time per connection
/// (single-writer discipline, mirroring the kernel's -EBUSY rule from the
/// client side: this loop is strictly sequential).
pub fn run_responder(stream: UnixStream) {
    let mut reader = BufReader::new(stream);
    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => break, // client closed
            Ok(_) => {
                let resp = respond(&line);
                let w: &mut dyn Write = reader.get_mut();
                if w.write_all(resp.as_bytes()).is_err() || w.flush().is_err() {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}
