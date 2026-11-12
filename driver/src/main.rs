//! `driver`: userspace client for the in-kernel Forth repl.
//!
//! Transport: real debugfs file (/sys/kernel/debug/forth/repl) or `--mock`
//! (socketpair to an in-process mock responder implementing the protocol
//! spec byte-for-byte).
//!
//! Modes:
//!   driver [--mock] [--repl PATH]            interactive REPL (`> ` prompt)
//!   driver [--mock] --eval "sentence"        batch: stdout + exit code
//!   driver --self-test                       conformance self-test (mock)

mod mock;
mod proto;
mod render;

use proto::{Outcome, Value, MAX_LINE};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, IsTerminal, Write};
use std::os::unix::net::UnixStream;

const REAL_REPL: &str = "/sys/kernel/debug/forth/repl";
/// Hard cap on response lines per eval (kernel caps response at 32768
/// bytes; this is the client-side backstop against a non-terminating read).
const MAX_RESP_LINES: usize = 16_384;

/// Single-writer discipline is enforced by `&mut`: only one outstanding
/// `transact` per client exists by construction (same rule as the kernel's
/// -EBUSY, client side).
enum Transport {
    File { write: File, read: BufReader<File> },
    Socket { write: UnixStream, read: BufReader<UnixStream> },
}

fn open_real(path: &str) -> Result<Transport, String> {
    let write = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| format!("open {path}: {e} (PENDING-WES: insmod first?)"))?;
    let clone = write.try_clone().map_err(|e| format!("clone {path}: {e}"))?;
    Ok(Transport::File { write, read: BufReader::new(clone) })
}

fn open_mock() -> Result<Transport, String> {
    let (client, server) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    std::thread::spawn(move || mock::run_responder(server));
    let clone = client.try_clone().map_err(|e| format!("clone socket: {e}"))?;
    Ok(Transport::Socket { write: client, read: BufReader::new(clone) })
}

/// Write one line, read to the sentinel, parse framing. Returns the raw
/// lines plus the parsed outcome.
fn transact(t: &mut Transport, line: &str) -> Result<(Vec<String>, Outcome), String> {
    if line.len() > MAX_LINE {
        return Err(format!("line too long: {} bytes > {MAX_LINE} (E2BIG, no eval)", line.len()));
    }
    if line.bytes().any(|b| b == b'\n' || b == b'\r') {
        return Err("request must be a single line".to_string());
    }
    let (w, r): (&mut dyn Write, &mut dyn BufRead) = match t {
        Transport::File { write, read } => (write, read),
        Transport::Socket { write, read } => (write, read),
    };
    w.write_all(line.as_bytes()).map_err(|e| format!("write: {e}"))?;
    w.write_all(b"\n").map_err(|e| format!("write: {e}"))?;
    w.flush().map_err(|e| format!("flush: {e}"))?;
    let mut lines = Vec::new();
    loop {
        let mut s = String::new();
        let n = r.read_line(&mut s).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("truncated response: EOF before sentinel".to_string());
        }
        while s.ends_with(['\n', '\r']) {
            s.pop();
        }
        let is_sentinel = s == "ok" || s == "err" || s.starts_with("err ");
        lines.push(s);
        if is_sentinel {
            break;
        }
        if lines.len() > MAX_RESP_LINES {
            return Err(format!("response exceeds {MAX_RESP_LINES} lines without sentinel"));
        }
    }
    let outcome = proto::parse_response(&lines)?;
    Ok((lines, outcome))
}

fn usage() -> ! {
    eprint!(
        "usage: driver [--mock] [--repl PATH] [--eval \"sentence\" | --self-test]\n\
         \n\
         transport: --mock (in-process mock responder) or --repl PATH\n\
         (default {REAL_REPL}). modes: interactive REPL (default),\n\
         --eval \"sentence\" (batch), --self-test (conformance, mock).\n\
         REPL: every line is eval'd; Ctrl-D quits.\n"
    );
    std::process::exit(2);
}

fn run_eval(t: &mut Transport, sentence: &str) -> i32 {
    match transact(t, sentence) {
        Ok((_, Outcome::Ok(values))) => {
            for l in render::render(&values) {
                println!("{l}");
            }
            0
        }
        Ok((_, Outcome::Err(msg))) => {
            if msg.is_empty() {
                eprintln!("err");
            } else {
                eprintln!("err {msg}");
            }
            1
        }
        Err(e) => {
            eprintln!("driver: {e}");
            2
        }
    }
}

fn run_repl(t: &mut Transport) -> i32 {
    let tty = std::io::stdin().is_terminal();
    // Prompt mirrors the protocol spec's example transcript (`> `).
    // Note: upstream rustforth has no interactive prompt at all (eval-only
    // CLI printing `[i] json`); there is no prompt string to copy, so the
    // spec transcript is the style source. See receipt.
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        if tty {
            print!("> ");
            std::io::stdout().flush().ok();
        }
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        match transact(t, line.trim_end()) {
            Ok((_, Outcome::Ok(values))) => {
                for l in render::render(&values) {
                    println!("{l}");
                }
            }
            Ok((_, Outcome::Err(msg))) => {
                if msg.is_empty() {
                    println!("err");
                } else {
                    println!("err {msg}");
                }
            }
            Err(e) => {
                eprintln!("driver: {e}");
                return 1;
            }
        }
    }
    0
}

// ---------- conformance self-test (always against the mock) ----------

fn check(name: &str, pass: &mut u32, fail: &mut u32, cond: bool, detail: String) {
    if cond {
        *pass += 1;
        println!("PASS: {name} {detail}");
    } else {
        *fail += 1;
        println!("FAIL: {name} {detail}");
    }
}

fn run_self_test() -> i32 {
    let mut pass = 0u32;
    let mut fail = 0u32;

    // Demo sentence list, transacted against --mock, framing asserted.
    let mut t = match open_mock() {
        Ok(t) => t,
        Err(e) => {
            println!("FAIL: open mock transport: {e}");
            return 1;
        }
    };
    let cases: &[(&str, Outcome)] = &[
        ("2 3 + .", Outcome::Ok(vec![Value::Text("5".into())])),
        (
            "unix orphans peers",
            Outcome::Ok(vec![Value::Ints(vec![18412, 18586])]),
        ),
        ("tasks fileless count", Outcome::Ok(vec![Value::Int(1)])),
        (
            "do_exit",
            Outcome::Ok(vec![Value::Text("do_exit 0xffffffffa1b2c3d4".into())]),
        ),
        ("frobnicate", Outcome::Err("undefined word: frobnicate".to_string())),
    ];
    for (sentence, want) in cases {
        match transact(&mut t, sentence) {
            Ok((raw, got)) => {
                let framing_ok = raw.last().is_some_and(|s| s == "ok" || s.starts_with("err"));
                let body_tags_known = raw[..raw.len() - 1].iter().all(|l| {
                    let tag = l.split(' ').next().unwrap_or("");
                    proto::KNOWN_TAGS.contains(&tag) && tag != "ok" && tag != "err"
                });
                let eq = &got == want;
                check(
                    &format!("mock {sentence:?}"),
                    &mut pass,
                    &mut fail,
                    framing_ok && body_tags_known && eq,
                    format!("raw={raw:?}"),
                );
            }
            Err(e) => check(
                &format!("mock {sentence:?}"),
                &mut pass,
                &mut fail,
                false,
                format!("transport error: {e}"),
            ),
        }
    }
    // `mem` shape (value is live MemTotal, so assert type/range, not bytes).
    match transact(&mut t, "mem") {
        Ok((_, Outcome::Ok(vals))) => {
            let ok_shape = matches!(&vals[..], [Value::Int(n)] if *n > 0);
            check("mock \"mem\"", &mut pass, &mut fail, ok_shape, format!("vals={vals:?}"));
        }
        other => check("mock \"mem\"", &mut pass, &mut fail, false, format!("{other:?}")),
    }
    // Parser probes: every tag parses, malformed framing is rejected loudly.
    let parse_cases: &[(&str, Vec<String>, bool)] = &[
        ("tag int", vec!["int 5".into(), "ok".into()], true),
        ("tag ints", vec!["ints 1 2 3".into(), "ok".into()], true),
        ("tag ints-empty", vec!["ints".into(), "ok".into()], true),
        ("tag task", vec!["task 4242 python 1000".into(), "ok".into()], true),
        (
            "tag unix",
            vec!["unix 18412 - 4242,4313 18586".into(), "ok".into()],
            true,
        ),
        (
            "tag tcp",
            vec!["tcp 9911 0.0.0.0:22 0.0.0.0:0 LISTEN -".into(), "ok".into()],
            true,
        ),
        (
            "tag uring",
            vec!["uring 4242 3 77120 no".into(), "ok".into()],
            true,
        ),
        ("tag text", vec!["text hello world".into(), "ok".into()], true),
        ("tag text-empty", vec!["text".into(), "ok".into()], true),
        ("empty result", vec!["ok".into()], true),
        ("err with message", vec!["err undefined word: frobnicate".into()], false),
        ("err bare", vec!["err".into()], false),
        ("unknown tag rejected", vec!["slab foo 1 2".into(), "ok".into()], false),
        ("ok-with-fields rejected", vec!["ok extra".into()], false),
        ("sentinel-in-body rejected", vec!["err boom".into(), "ok".into()], false),
        ("missing sentinel rejected", vec!["int 5".into()], false),
        ("empty response rejected", vec![], false),
        ("err-with-values rejected", vec!["int 5".into(), "err boom".into()], false),
    ];
    for (name, lines, want_ok_values) in parse_cases {
        let r = proto::parse_response(lines);
        // `want_ok_values=false` covers both parsed-Err outcomes and
        // correctly-parsed `err` sentinels: assert exact shape instead.
        let good = match (&r, *name) {
            (Ok(Outcome::Ok(_)), _) => *want_ok_values,
            (Ok(Outcome::Err(_)), "err with message" | "err bare") => true,
            (Ok(_), _) => false,
            (Err(_), "err with message" | "err bare") => false,
            (Err(_), _) => !want_ok_values,
        };
        check(name, &mut pass, &mut fail, good, format!("lines={lines:?}"));
    }
    // Render probes: every tag has a deterministic plain-table shape.
    let render_cases: &[(Value, &[&str])] = &[
        (Value::Int(5), &["int 5"]),
        (Value::Ints(vec![18412, 18586]), &["ints 18412 18586"]),
        (Value::Ints(vec![]), &["ints (empty)"]),
        (
            Value::Task { pid: 4242, comm: "python".into(), uid: 1000 },
            &["TASK PID COMM UID", "task 4242 python 1000"],
        ),
        (
            Value::Unix { ino: 18412, name: "-".into(), owners: "4242".into(), peer: "18586".into() },
            &["UNIX INO NAME OWNERS PEER", "unix 18412 - 4242 18586"],
        ),
        (
            Value::Tcp {
                ino: 9911,
                laddr: "0.0.0.0:22".into(),
                raddr: "0.0.0.0:0".into(),
                state: "LISTEN".into(),
                owners: "-".into(),
            },
            &["TCP INO LADDR RADDR STATE OWNERS", "tcp 9911 0.0.0.0:22 0.0.0.0:0 LISTEN -"],
        ),
        (
            Value::Uring { owner: "4242".into(), fd: 3, ino: 77120, sqpoll: "no".into() },
            &["URING OWNER FD INO SQPOLL", "uring 4242 3 77120 no"],
        ),
        (Value::Text("hi".into()), &["hi"]),
    ];
    for (v, want) in render_cases {
        let got = render::render(std::slice::from_ref(v));
        check(
            "render",
            &mut pass,
            &mut fail,
            got.iter().map(String::as_str).collect::<Vec<_>>() == *want,
            format!("{v:?} -> {got:?}"),
        );
    }
    // Over-long request rejected client-side (E2BIG mirror).
    let big = "x".repeat(MAX_LINE + 1);
    check(
        "E2BIG local reject",
        &mut pass,
        &mut fail,
        transact(&mut t, &big).is_err(),
        format!("{} bytes", big.len()),
    );

    println!("SELF-TEST: {} pass, {} fail", pass, fail);
    if fail == 0 { 0 } else { 1 }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut use_mock = false;
    let mut repl_path: Option<String> = None;
    let mut eval: Option<String> = None;
    let mut self_test = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--mock" => use_mock = true,
            "--repl" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                repl_path = Some(args[i].clone());
            }
            "--eval" => {
                i += 1;
                if i >= args.len() {
                    usage();
                }
                eval = Some(args[i].clone());
            }
            "--self-test" => self_test = true,
            "-h" | "--help" => usage(),
            _ => usage(),
        }
        i += 1;
    }
    if self_test && eval.is_some() {
        eprintln!("driver: --self-test and --eval are exclusive");
        std::process::exit(2);
    }
    if self_test {
        std::process::exit(run_self_test());
    }
    let t = if use_mock {
        open_mock()
    } else {
        open_real(repl_path.as_deref().unwrap_or(REAL_REPL))
    };
    let mut t = match t {
        Ok(t) => t,
        Err(e) => {
            eprintln!("driver: {e}");
            std::process::exit(2);
        }
    };
    match eval {
        Some(s) => std::process::exit(run_eval(&mut t, &s)),
        None => std::process::exit(run_repl(&mut t)),
    }
}
