//! `helix-cli` — `bitcoin-cli` for the Helix wallet RPC: the same command line (`-rpcport=…`,
//! `-datadir=…`, `-named`, `-stdin`, `-rpcwait`), the same output, the same exit codes, so an
//! exchange's operations scripts work with one word changed.
//!
//! `-datadir` is the wallet's directory: credentials come from `-rpcuser`/`-rpcpassword`, else
//! `rpcuser`/`rpcpassword` in its `helix.conf`, else the cookie the wallet RPC writes there.
//!
//! **Amounts are passed and printed as their digits.** A parameter that is a number goes into the
//! request as typed, and the answer is indented as text — never read into a double, which would
//! print 2.01 as 2.0099999999999998 or lose nano-HLX above ~9 million HLX.

use std::io::BufRead;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine;
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::conf::Conf;

const USAGE: &str = "\
Usage: helix-cli [options] <command> [params]   (or: helix rpc [options] <command> [params])

Calls the Helix wallet RPC, as bitcoin-cli calls Bitcoin Core's.

Options:
  -datadir=<dir>          the wallet's directory (default: $HELIX_WALLET_DIR or helix-wallet)
  -conf=<file>            helix.conf to read (default: <datadir>/helix.conf)
  -rpcconnect=<host>      where the wallet RPC listens (default: 127.0.0.1)
  -rpcport=<port>         its port (default: rpcport in helix.conf, else 8547)
  -rpcuser=<user>         user, with -rpcpassword (default: helix.conf, else the cookie)
  -rpcpassword=<pw>       its password
  -rpccookiefile=<file>   the cookie (default: <datadir>/.cookie)
  -named                  parameters as name=value
  -stdin                  read further parameters from standard input, one per line
  -stdinrpcpass           read the RPC password from the first line of standard input
  -rpcwait                wait for the wallet RPC to come up
  -rpcclienttimeout=<s>   give up after this many seconds (default 900, 0 = never)
  -help                   this text
  -version                the version

Run `helix-cli help` for the methods the wallet offers.";

/// Parameters that are JSON (numbers, booleans, objects), by method and position — as
/// bitcoin-cli's table; every other parameter is a string, whatever it looks like.
const JSON_PARAMS: &[(&str, usize, &str)] = &[
    ("getblockhash", 0, "height"),
    ("getblock", 1, "verbosity"),
    ("getrawtransaction", 1, "verbose"),
    ("getbalance", 1, "minconf"),
    ("getbalance", 2, "include_watchonly"),
    ("getbalance", 3, "avoid_reuse"),
    ("getreceivedbyaddress", 1, "minconf"),
    ("listsinceblock", 1, "target_confirmations"),
    ("listsinceblock", 2, "include_watchonly"),
    ("listsinceblock", 3, "include_removed"),
    ("listtransactions", 1, "count"),
    ("listtransactions", 2, "skip"),
    ("listtransactions", 3, "include_watchonly"),
    ("gettransaction", 1, "include_watchonly"),
    ("gettransaction", 2, "verbose"),
    ("sendtoaddress", 1, "amount"),
    ("sendtoaddress", 4, "subtractfeefromamount"),
    ("sendtoaddress", 5, "replaceable"),
    ("sendtoaddress", 6, "conf_target"),
    ("sendtoaddress", 8, "avoid_reuse"),
    ("sendmany", 1, "amounts"),
    ("sendmany", 2, "minconf"),
    ("sendmany", 4, "subtractfeefrom"),
    ("estimatesmartfee", 0, "conf_target"),
    ("settxfee", 0, "amount"),
    ("walletpassphrase", 1, "timeout"),
    ("keypoolrefill", 0, "newsize"),
];

fn is_json(method: &str, index: usize, name: Option<&str>) -> bool {
    JSON_PARAMS.iter().any(|(m, i, n)| *m == method && name.map_or(*i == index, |name| *n == name))
}

/// A parameter as request text: as typed where the method takes JSON there, a string elsewhere.
fn param_text(method: &str, index: usize, name: Option<&str>, value: &str) -> Result<String, String> {
    if is_json(method, index, name) {
        serde_json::from_str::<Box<RawValue>>(value).map(|raw| raw.get().to_string()).map_err(|_| format!("Error parsing JSON: {value}"))
    } else {
        Ok(serde_json::to_string(value).expect("a string serializes"))
    }
}

/// The request body for `method` with `args`, positional or `-named`.
pub fn request_body(method: &str, args: &[String], named: bool) -> Result<String, String> {
    let params = if named {
        let mut pairs = Vec::new();
        for arg in args {
            let (name, value) = arg.split_once('=').ok_or_else(|| format!("No '=' in named argument '{arg}', this may be because you forgot to use -named"))?;
            pairs.push(format!("{}:{}", serde_json::to_string(name).expect("a string"), param_text(method, 0, Some(name), value)?));
        }
        format!("{{{}}}", pairs.join(","))
    } else {
        let list: Result<Vec<String>, String> = args.iter().enumerate().map(|(i, v)| param_text(method, i, None, v)).collect();
        format!("[{}]", list?.join(","))
    };
    Ok(format!(
        "{{\"jsonrpc\":\"1.0\",\"id\":\"helix-cli\",\"method\":{},\"params\":{params}}}",
        serde_json::to_string(method).expect("a string")
    ))
}

/// JSON text indented two spaces, as bitcoin-cli prints a result — re-spaced as text, so every
/// number keeps its digits.
pub fn pretty(json: &str) -> String {
    let chars: Vec<char> = json.chars().collect();
    let mut out = String::with_capacity(json.len() * 2);
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    let mut i = 0;
    let newline = |out: &mut String, depth: usize| {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    };
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '{' | '[' => {
                let close = if c == '{' { '}' } else { ']' };
                let mut j = i + 1;
                while j < chars.len() && chars[j].is_whitespace() {
                    j += 1;
                }
                if chars.get(j) == Some(&close) {
                    out.push(c);
                    out.push(close);
                    i = j + 1;
                    continue;
                }
                depth += 1;
                out.push(c);
                newline(&mut out, depth);
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                newline(&mut out, depth);
                out.push(c);
            }
            ',' => {
                out.push(',');
                newline(&mut out, depth);
            }
            ':' => out.push_str(": "),
            c if c.is_whitespace() => {}
            c => out.push(c),
        }
        i += 1;
    }
    out
}

#[derive(Debug, Default)]
struct Options {
    datadir: Option<PathBuf>,
    conf: Option<PathBuf>,
    rpcconnect: Option<String>,
    rpcport: Option<u16>,
    rpcuser: Option<String>,
    rpcpassword: Option<String>,
    rpccookiefile: Option<PathBuf>,
    named: bool,
    stdin: bool,
    stdinrpcpass: bool,
    rpcwait: bool,
    timeout: Option<u64>,
    help: bool,
    version: bool,
}

/// The options before the method, and what follows.
fn parse_options(args: &[String]) -> Result<(Options, Vec<String>), String> {
    let mut o = Options::default();
    let mut rest = args.iter();
    let mut remaining: Vec<String> = Vec::new();
    for arg in rest.by_ref() {
        if !arg.starts_with('-') || arg.len() < 2 {
            remaining.push(arg.clone());
            break;
        }
        let bare = arg.trim_start_matches('-');
        let (key, value) = match bare.split_once('=') {
            Some((k, v)) => (k, Some(v.to_string())),
            None => (bare, None),
        };
        let flag = |v: &Option<String>| -> Result<bool, String> {
            match v.as_deref() {
                None | Some("1") => Ok(true),
                Some("0") => Ok(false),
                Some(other) => Err(format!("Invalid value for -{key}: {other}")),
            }
        };
        let value_of = |v: Option<String>| v.ok_or_else(|| format!("-{key} needs a value (-{key}=...)"));
        match key {
            "datadir" => o.datadir = Some(PathBuf::from(value_of(value)?)),
            "conf" => o.conf = Some(PathBuf::from(value_of(value)?)),
            "rpcconnect" => o.rpcconnect = Some(value_of(value)?),
            "rpcport" => o.rpcport = Some(value_of(value)?.parse().map_err(|_| format!("Invalid port for -rpcport: {arg}"))?),
            "rpcuser" => o.rpcuser = Some(value_of(value)?),
            "rpcpassword" => o.rpcpassword = Some(value_of(value)?),
            "rpccookiefile" => o.rpccookiefile = Some(PathBuf::from(value_of(value)?)),
            "named" => o.named = flag(&value)?,
            "stdin" => o.stdin = flag(&value)?,
            "stdinrpcpass" => o.stdinrpcpass = flag(&value)?,
            "rpcwait" => o.rpcwait = flag(&value)?,
            "rpcclienttimeout" => o.timeout = Some(value_of(value)?.parse().map_err(|_| format!("Invalid value for -rpcclienttimeout: {arg}"))?),
            "help" | "h" | "?" => o.help = true,
            "version" => o.version = true,
            _ => return Err(format!("Error parsing command line arguments: Invalid parameter {arg}")),
        }
    }
    remaining.extend(rest.cloned());
    Ok((o, remaining))
}

/// `host`, `host:port` or `[v6]:port` as `rpcconnect` may give it.
fn host_port(connect: &str, port: u16) -> (String, u16) {
    if let Some(rest) = connect.strip_prefix('[') {
        if let Some((host, tail)) = rest.split_once(']') {
            let port = tail.strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(port);
            return (format!("[{host}]"), port);
        }
    }
    match connect.rsplit_once(':') {
        Some((host, p)) if !host.contains(':') => (host.to_string(), p.parse().unwrap_or(port)),
        _ if connect.contains(':') => (format!("[{connect}]"), port),
        _ => (connect.to_string(), port),
    }
}

#[derive(Deserialize)]
struct Reply {
    result: Option<Box<RawValue>>,
    error: Option<ReplyError>,
}

#[derive(Deserialize)]
struct ReplyError {
    code: i64,
    message: String,
}

fn fail(message: impl std::fmt::Display) -> i32 {
    eprintln!("{message}");
    1
}

/// Run `helix-cli` with `args` (without the program name). Returns the exit code.
pub async fn main(args: Vec<String>) -> i32 {
    let (mut o, mut rest) = match parse_options(&args) {
        Ok(parsed) => parsed,
        Err(e) => return fail(format!("error: {e}")),
    };
    // Before the check for a missing command: `-version` comes without one, and asking it after that
    // check printed the usage and exited 1 — what 0.20.3 shipped.
    if o.version {
        println!("Helix RPC client version v{}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if o.help || (rest.is_empty() && !o.stdin) {
        println!("{USAGE}");
        return if o.help { 0 } else { 1 };
    }
    if o.stdin || o.stdinrpcpass {
        let mut lines = std::io::stdin().lock().lines();
        if o.stdinrpcpass {
            match lines.next() {
                Some(Ok(line)) => o.rpcpassword = Some(line),
                _ => return fail("error: -stdinrpcpass given, but nothing on standard input"),
            }
        }
        if o.stdin {
            for line in lines {
                match line {
                    Ok(line) => rest.push(line),
                    Err(e) => return fail(format!("error: reading standard input: {e}")),
                }
            }
        }
    }
    let Some((method, params)) = rest.split_first() else {
        return fail("error: too few parameters (need at least command)");
    };

    let datadir = o.datadir.clone().unwrap_or_else(|| PathBuf::from(std::env::var("HELIX_WALLET_DIR").unwrap_or_else(|_| "helix-wallet".into())));
    let conf_path = match &o.conf {
        Some(c) if c.is_absolute() => c.clone(),
        Some(c) => datadir.join(c),
        None => datadir.join(crate::conf::FILE),
    };
    let conf = match Conf::read_file(&conf_path, crate::cli::NETWORK) {
        Ok(c) => c.unwrap_or_default(),
        Err(e) => return fail(format!("error: {e:#}")),
    };
    let port = o.rpcport.or(conf.rpcport).unwrap_or(crate::cli::DEFAULT_PORT);
    let connect = o.rpcconnect.clone().or(conf.rpcconnect.clone()).unwrap_or_else(|| "127.0.0.1".into());
    let (host, port) = host_port(&connect, port);
    let credentials = match (o.rpcuser.clone().or(conf.rpcuser.clone()), o.rpcpassword.clone().or(conf.rpcpassword.clone())) {
        (Some(user), Some(password)) => format!("{user}:{password}"),
        _ => {
            let cookie = o.rpccookiefile.clone().map(|c| if c.is_absolute() { c } else { datadir.join(c) }).unwrap_or_else(|| match &conf.rpccookiefile {
                Some(c) if std::path::Path::new(c).is_absolute() => PathBuf::from(c),
                Some(c) => datadir.join(c),
                None => datadir.join(".cookie"),
            });
            match std::fs::read_to_string(&cookie) {
                Ok(pair) => pair.trim().to_string(),
                Err(_) => {
                    return fail(format!(
                        "error: Could not locate RPC credentials. No authentication cookie could be found at {}, and \
                         no rpcuser/rpcpassword is set. Is the wallet RPC running, and is -datadir its directory?",
                        cookie.display()
                    ))
                }
            }
        }
    };
    let body = match request_body(method, params, o.named) {
        Ok(b) => b,
        Err(e) => return fail(format!("error: {e}")),
    };

    let mut client = reqwest::Client::builder();
    match o.timeout.unwrap_or(900) {
        0 => {}
        secs => client = client.timeout(Duration::from_secs(secs)),
    }
    let client = client.build().expect("a TLS backend is available");
    let url = format!("http://{host}:{port}/");
    let auth = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(credentials));
    let response = loop {
        match client.post(&url).header("Authorization", &auth).header("Content-Type", "application/json").body(body.clone()).send().await {
            Ok(r) => break r,
            Err(e) if o.rpcwait && (e.is_connect() || e.is_request()) => tokio::time::sleep(Duration::from_secs(1)).await,
            Err(e) => {
                return fail(format!(
                    "error: Could not connect to the server {host}:{port}\n\nMake sure the Helix wallet RPC is running \
                     (server=1 in {}, or HELIX_WALLET_RPC) and that -rpcport and -rpcconnect point at it. ({e})",
                    conf_path.display()
                ))
            }
        }
    };
    let status = response.status();
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return fail("error: Authorization failed: Incorrect rpcuser or rpcpassword");
    }
    if status == reqwest::StatusCode::FORBIDDEN {
        return fail("error: server returned HTTP error 403 — this address is not allowed (rpcallowip)");
    }
    let text = match response.text().await {
        Ok(t) => t,
        Err(e) => return fail(format!("error: the answer broke off: {e}")),
    };
    let reply: Reply = match serde_json::from_str(&text) {
        Ok(r) => r,
        Err(_) => return fail(format!("error: server returned HTTP error {}", status.as_u16())),
    };
    if let Some(error) = reply.error {
        eprintln!("error code: {}\nerror message:\n{}", error.code, error.message);
        return error.code.unsigned_abs().min(i32::MAX as u64) as i32;
    }
    match reply.result.as_deref().map(|r| r.get().trim()) {
        None | Some("null") => {}
        Some(text) if text.starts_with('"') => match serde_json::from_str::<String>(text) {
            Ok(s) => println!("{s}"),
            Err(_) => println!("{text}"),
        },
        Some(text) => println!("{}", pretty(text)),
    }
    0
}

#[cfg(test)]
mod tests {

    /// `helix-cli -version` names the version and exits 0, as `bitcoin-cli -version` does — with
    /// no command after it, which is how it is called. Without one and without `-version` it is the
    /// usage and exit 1, again as `bitcoin-cli`.
    #[tokio::test]
    async fn the_version_is_answered_without_a_command() {
        assert_eq!(main(vec!["-version".into()]).await, 0);
        assert_eq!(main(vec!["-help".into()]).await, 0);
        assert_eq!(main(Vec::new()).await, 1);
    }

    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// As bitcoin-cli: a number goes in as the number typed where the method takes one, and a
    /// label or passphrase made of digits stays a string.
    #[test]
    fn parameters_are_json_where_the_method_takes_json_and_strings_elsewhere() {
        assert_eq!(
            request_body("sendtoaddress", &args(&["hlxAbc", "2.010000001", "", "", "true"]), false).unwrap(),
            r#"{"jsonrpc":"1.0","id":"helix-cli","method":"sendtoaddress","params":["hlxAbc",2.010000001,"","",true]}"#
        );
        assert_eq!(
            request_body("walletpassphrase", &args(&["123456", "60"]), false).unwrap(),
            r#"{"jsonrpc":"1.0","id":"helix-cli","method":"walletpassphrase","params":["123456",60]}"#
        );
        assert_eq!(
            request_body("getnewaddress", &args(&["42"]), false).unwrap(),
            r#"{"jsonrpc":"1.0","id":"helix-cli","method":"getnewaddress","params":["42"]}"#
        );
        assert_eq!(
            request_body("getblock", &args(&["blockhash=ab", "verbosity=2"]), true).unwrap(),
            r#"{"jsonrpc":"1.0","id":"helix-cli","method":"getblock","params":{"blockhash":"ab","verbosity":2}}"#
        );
        assert!(request_body("getblockhash", &args(&["ten"]), false).unwrap_err().contains("Error parsing JSON"));
        assert!(request_body("getblock", &args(&["ab"]), true).unwrap_err().contains("-named"));
    }

    /// The printed result keeps every digit — through a double, 33000000.000000001 is 33000000.0.
    #[test]
    fn a_result_is_indented_with_every_digit_kept() {
        let raw = r#"{"balance":33000000.000000001,"list":[1,"a,b:{c}",{}],"empty":[],"s":"q\"x"}"#;
        assert_eq!(
            pretty(raw),
            "{\n  \"balance\": 33000000.000000001,\n  \"list\": [\n    1,\n    \"a,b:{c}\",\n    {}\n  ],\n  \"empty\": [],\n  \"s\": \"q\\\"x\"\n}"
        );
        let back: serde_json::Value = serde_json::from_str(&pretty(raw)).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(raw).unwrap(), "the same JSON, re-spaced");
    }

    #[test]
    fn the_options_are_bitcoin_clis() {
        let (o, rest) = parse_options(&args(&["-datadir=/w", "--rpcport=18547", "-named", "getblock", "-1"])).unwrap();
        assert_eq!((o.datadir, o.rpcport, o.named), (Some(PathBuf::from("/w")), Some(18547), true));
        assert_eq!(rest, args(&["getblock", "-1"]), "after the method, a dash is a parameter");
        assert!(parse_options(&args(&["-rpcprot=1", "help"])).unwrap_err().contains("Invalid parameter"));
        assert!(parse_options(&args(&["-rpcport=x", "help"])).unwrap_err().contains("Invalid port"));
        assert_eq!(host_port("10.0.0.5", 8547), ("10.0.0.5".to_string(), 8547));
        assert_eq!(host_port("10.0.0.5:9000", 8547), ("10.0.0.5".to_string(), 9000));
        assert_eq!(host_port("::1", 8547), ("[::1]".to_string(), 8547));
        assert_eq!(host_port("[::1]:9000", 8547), ("[::1]".to_string(), 9000));
    }
}
