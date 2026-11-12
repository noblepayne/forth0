//! Plain-table rendering, one tag at a time. No TUI, no colors:
//! deterministic stdout safe for screenshot captures.

use crate::proto::Value;

/// Render parsed values to display lines (no trailing newline included).
pub fn render(values: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    let mut task_hdr = false;
    let mut unix_hdr = false;
    let mut tcp_hdr = false;
    let mut uring_hdr = false;
    for v in values {
        match v {
            Value::Int(n) => out.push(format!("int {n}")),
            Value::Ints(ns) => {
                if ns.is_empty() {
                    out.push("ints (empty)".to_string());
                } else {
                    out.push(format!(
                        "ints {}",
                        ns.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(" ")
                    ));
                }
            }
            Value::Task { pid, comm, uid } => {
                if !task_hdr {
                    task_hdr = true;
                    out.push("TASK PID COMM UID".to_string());
                }
                out.push(format!("task {pid} {comm} {uid}"));
            }
            Value::Unix { ino, name, owners, peer } => {
                if !unix_hdr {
                    unix_hdr = true;
                    out.push("UNIX INO NAME OWNERS PEER".to_string());
                }
                out.push(format!("unix {ino} {name} {owners} {peer}"));
            }
            Value::Tcp { ino, laddr, raddr, state, owners } => {
                if !tcp_hdr {
                    tcp_hdr = true;
                    out.push("TCP INO LADDR RADDR STATE OWNERS".to_string());
                }
                out.push(format!("tcp {ino} {laddr} {raddr} {state} {owners}"));
            }
            Value::Uring { owner, fd, ino, sqpoll } => {
                if !uring_hdr {
                    uring_hdr = true;
                    out.push("URING OWNER FD INO SQPOLL".to_string());
                }
                out.push(format!("uring {owner} {fd} {ino} {sqpoll}"));
            }
            // Output capture (`.` word, `.s`, diagnostics): raw, unprefixed.
            Value::Text(s) => out.push(s.clone()),
        }
    }
    out
}
