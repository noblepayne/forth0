//! Line-protocol v0.1 types: response framing + typed-line parsing.
//!
//! Contract: spec/line-protocol-v0.1.md. The driver rejects unknown tags
//! loudly (never renders a column as the wrong type).

/// Max request size in bytes (spec: longer -> -E2BIG, no eval).
pub const MAX_LINE: usize = 4096;

/// Sentinel / tag literals.
pub const KNOWN_TAGS: &[&str] = &[
    "int", "ints", "task", "unix", "tcp", "uring", "text", "ok", "err",
];

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Ints(Vec<i64>),
    Task { pid: u64, comm: String, uid: u32 },
    Unix { ino: u64, name: String, owners: String, peer: String },
    Tcp { ino: u64, laddr: String, raddr: String, state: String, owners: String },
    Uring { owner: String, fd: i64, ino: u64, sqpoll: String },
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    Ok(Vec<Value>),
    Err(String),
}

/// Split a line into (tag, rest-after-first-space).
fn split_tag(line: &str) -> (&str, &str) {
    match line.find(' ') {
        Some(i) => (&line[..i], &line[i + 1..]),
        None => (line, ""),
    }
}

fn parse_i64(s: &str) -> Result<i64, String> {
    s.parse::<i64>()
        .map_err(|_| format!("bad i64 field: {s:?}"))
}

/// Parse one non-sentinel value line. Unknown tags are an error (loud).
pub fn parse_value(line: &str) -> Result<Value, String> {
    let (tag, rest) = split_tag(line);
    match tag {
        "int" => {
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() != 1 {
                return Err(format!("`int` wants exactly 1 field, got {}: {line:?}", f.len()));
            }
            Ok(Value::Int(parse_i64(f[0])?))
        }
        "ints" => {
            let mut out = Vec::new();
            for f in rest.split_whitespace() {
                out.push(parse_i64(f)?);
            }
            Ok(Value::Ints(out))
        }
        "task" => {
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() != 3 {
                return Err(format!("`task` wants 3 fields <pid> <comm> <uid>, got {}: {line:?}", f.len()));
            }
            let pid: u64 = f[0].parse().map_err(|_| format!("bad pid: {:?}", f[0]))?;
            let uid: u32 = f[2].parse().map_err(|_| format!("bad uid: {:?}", f[2]))?;
            Ok(Value::Task { pid, comm: f[1].to_string(), uid })
        }
        "unix" => {
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() != 4 {
                return Err(format!(
                    "`unix` wants 4 fields <ino> <name> <owners|-> <peer|->, got {}: {line:?}",
                    f.len()
                ));
            }
            let ino: u64 = f[0].parse().map_err(|_| format!("bad ino: {:?}", f[0]))?;
            Ok(Value::Unix {
                ino,
                name: f[1].to_string(),
                owners: f[2].to_string(),
                peer: f[3].to_string(),
            })
        }
        "tcp" => {
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() != 5 {
                return Err(format!(
                    "`tcp` wants 5 fields <ino> <laddr> <raddr> <state> <owners|->, got {}: {line:?}",
                    f.len()
                ));
            }
            let ino: u64 = f[0].parse().map_err(|_| format!("bad ino: {:?}", f[0]))?;
            Ok(Value::Tcp {
                ino,
                laddr: f[1].to_string(),
                raddr: f[2].to_string(),
                state: f[3].to_string(),
                owners: f[4].to_string(),
            })
        }
        "uring" => {
            let f: Vec<&str> = rest.split_whitespace().collect();
            if f.len() != 4 {
                return Err(format!(
                    "`uring` wants 4 fields <owner> <fd> <ino> <sqpoll>, got {}: {line:?}",
                    f.len()
                ));
            }
            let fd: i64 = f[1].parse().map_err(|_| format!("bad fd: {:?}", f[1]))?;
            let ino: u64 = f[2].parse().map_err(|_| format!("bad ino: {:?}", f[2]))?;
            Ok(Value::Uring {
                owner: f[0].to_string(),
                fd,
                ino,
                sqpoll: f[3].to_string(),
            })
        }
        "text" => Ok(Value::Text(rest.to_string())),
        "ok" | "err" => Err(format!("sentinel `{tag}` inside response body: {line:?}")),
        other => Err(format!(
            "unknown tag: {other:?} (known: {}) — refusing to render",
            KNOWN_TAGS.join(",")
        )),
    }
}

/// Validate framing: zero or more value lines, exactly one trailing sentinel
/// (`ok` with no fields, or `err [<message>]`). The sentinel must be last;
/// reading stops at the first sentinel, so anything that is not the final
/// line in this slice is a body line by construction.
pub fn parse_response(lines: &[String]) -> Result<Outcome, String> {
    if lines.is_empty() {
        return Err("truncated response: no sentinel (expected `ok` or `err <message>`)".into());
    }
    let (body, last) = (&lines[..lines.len() - 1], &lines[lines.len() - 1]);
    let mut values = Vec::with_capacity(body.len());
    for ln in body {
        values.push(parse_value(ln)?);
    }
    if last == "ok" {
        Ok(Outcome::Ok(values))
    } else if last == "err" || last.starts_with("err ") {
        let msg = last.strip_prefix("err ").unwrap_or("").to_string();
        let _ = &values;
        // An `err` sentinel carries no values: body must be empty.
        if !values.is_empty() {
            return Err(format!(
                "`err` sentinel with {} value lines before it (failure carries no values)",
                values.len()
            ));
        }
        Ok(Outcome::Err(msg))
    } else {
        // Last line is neither sentinel: either a value line with no
        // terminator (truncated read) or garbage.
        let (tag, _) = split_tag(last);
        if KNOWN_TAGS.contains(&tag) {
            Err(format!("truncated response: last line {last:?} is not a sentinel"))
        } else {
            Err(format!("bad sentinel {last:?} (want `ok` or `err <message>`)"))
        }
    }
}
