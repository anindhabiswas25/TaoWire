//! Sidecar client (feature `sidecar`, spec 11.6): a Rust miner gets its
//! caller policy and its chain writes from the Python sidecar (`tensorwire
//! sidecar`, loopback only, bearer token).
//!
//! ```ignore
//! let sidecar = Arc::new(SidecarClient::new(Config { expected_hotkey: Some(key.ss58().into()), ..Config::new(2) })?);
//! sidecar.start().await?; // first metagraph, then a refresh every 60 s
//! let auth = MinerAuth::new(verifier).with_response_key(key).with_policy(sidecar.policy());
//! let block_hash = sidecar.serve_axon("203.0.113.7", 8091, None).await?;
//! ```
//!
//! The snapshot is cached locally and judged with the three staleness stages
//! of spec 8.5.1 from the age and tempo the sidecar reports; the caller
//! policy is the Python kit's (`CallerPolicy`, `CallerGate`). Every answer is
//! parsed strictly and fails closed: anything unexpected rejects the answer
//! and never admits a caller. Wire shapes: `docs/multi-language.md`
//! ("Sidecar API").

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::error::{codes, Error};
use crate::ss58::decode_ss58;
use crate::verify::PolicyFn;

/// Default sidecar URL (`TW_SIDECAR_PORT` 9910 on loopback).
pub const DEFAULT_URL: &str = "http://127.0.0.1:9910";
/// Default refresh of the cached metagraph (spec 11.6).
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(60);
/// Default per-call timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
/// Block time used to turn a tempo into seconds (spec 8.5.1).
pub const BLOCK_TIME: Duration = Duration::from_secs(12);
/// Default `TW_METAGRAPH_SOFT_AGE_S`.
pub const DEFAULT_SOFT_AGE: Duration = Duration::from_secs(900);
/// Most neurons accepted in one snapshot.
pub const MAX_NEURONS: usize = 65_536;
/// Most remembered known callers.
pub const MAX_KNOWN_CALLERS: usize = 65_536;
/// Largest sidecar answer read.
pub const MAX_ANSWER_BYTES: usize = 32 << 20;
/// The known-callers scope of [`SidecarClient::policy`]. Never the raw request
/// path: a caller could invent paths to fill the bounded set and evict the
/// other validators during a chain outage.
pub const POLICY_SCOPE: &str = "middleware";
/// Token length bounds.
pub const TOKEN_LENGTH: std::ops::RangeInclusive<usize> = 16..=1024;

const FORBIDDEN_CODES: [&str; 5] = [
    "tw.forbidden_denied",
    "tw.forbidden_not_registered",
    "tw.forbidden_not_validator",
    "tw.forbidden_low_stake",
    codes::METAGRAPH_STALE,
];

/// Staleness stage of a snapshot (spec 8.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// Younger than the soft age.
    Fresh,
    /// Between the soft and the max age (both boundaries included).
    Degraded,
    /// Older than the max age, or no snapshot: only known callers.
    KnownCallersOnly,
}

/// One neuron of a sidecar snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct Neuron {
    /// UID on the subnet.
    pub uid: u16,
    /// SS58 hotkey.
    pub hotkey: String,
    /// Whether it holds a validator permit.
    pub validator_permit: bool,
    /// TAO value of its stake at spot price (approximate, D2).
    pub total_stake_tao: f64,
    /// Published endpoint, if any.
    pub axon: Option<String>,
}

/// A metagraph snapshot as the sidecar reported it.
#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Subnet.
    pub netuid: u16,
    /// Block the snapshot was read at.
    pub block: u64,
    /// Subnet tempo in blocks.
    pub tempo: u16,
    /// Age when the sidecar answered, seconds.
    pub age_s: f64,
    /// Neurons in UID order.
    pub neurons: Vec<Neuron>,
    index: HashMap<String, usize>,
}

impl Snapshot {
    /// Look a hotkey up.
    pub fn by_hotkey(&self, hotkey: &str) -> Option<&Neuron> {
        self.index.get(hotkey).map(|&i| &self.neurons[i])
    }
}

/// What `/v1/health` reports.
#[derive(Debug, Clone, PartialEq)]
pub struct Health {
    /// False when there is no snapshot or it is past the max age.
    pub ok: bool,
    /// The sidecar's hotkey (it publishes the axon for it).
    pub hotkey: String,
    /// Its subnet.
    pub netuid: u16,
    /// Snapshot block, `None` before the first.
    pub block: Option<u64>,
    /// Snapshot age, `None` before the first.
    pub metagraph_age_s: Option<f64>,
    /// The sidecar's own stage.
    pub stage: Stage,
}

/// The `/v1/caller` answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// `{"allowed": true}`.
    Allowed,
    /// `{"allowed": false, "code": ...}`.
    Refused(&'static str),
}

/// A `serve_axon` failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServeAxonError {
    /// The chain refused it (409) or could not be reached (503,
    /// `chain_unavailable`); `code` is the `bt.ErrorCode` value.
    #[error("serve-axon refused by the chain: {code}")]
    Chain {
        /// `bt.ErrorCode` value or `chain_unavailable`.
        code: String,
        /// The chain's error name, if any.
        error_name: Option<String>,
        /// The SDK's hint, if any.
        remediation: Option<String>,
    },
    /// Any other failure (transport, the sidecar's own error, a bad answer).
    #[error(transparent)]
    Other(#[from] Error),
}

// ---------------------------------------------------------------- token

/// Read the bearer token (`TW_SIDECAR_TOKEN_FILE`): a regular file only its
/// owner can read or write (the TLS key rule), 16–1024 printable ASCII
/// characters after one trailing newline is removed. Errors name the file,
/// never its contents. One open file is used for the mode check and the
/// read.
pub fn read_token_file(path: &Path) -> Result<String, String> {
    let shown = path.display();
    let mut f =
        std::fs::File::open(path).map_err(|_| format!("cannot open sidecar token file {shown}"))?;
    let meta = f.metadata().map_err(|_| format!("cannot read sidecar token file {shown}"))?;
    if !meta.is_file() {
        return Err(format!("sidecar token file {shown} is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "sidecar token file {shown} must not be readable or writable by group or others (chmod 600)"
            ));
        }
    }
    let mut data = Vec::new();
    f.by_ref()
        .take(*TOKEN_LENGTH.end() as u64 + 3)
        .read_to_end(&mut data)
        .map_err(|_| format!("cannot read sidecar token file {shown}"))?;
    let text = String::from_utf8(data).unwrap_or_default();
    let text = text.strip_suffix('\n').map(|t| t.strip_suffix('\r').unwrap_or(t)).unwrap_or(&text);
    check_token(text, &shown.to_string())
}

fn check_token(token: &str, place: &str) -> Result<String, String> {
    if !TOKEN_LENGTH.contains(&token.len()) || !token.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(format!(
            "the sidecar token from {place} must be {}-{} printable ASCII characters",
            TOKEN_LENGTH.start(),
            TOKEN_LENGTH.end()
        ));
    }
    Ok(token.to_owned())
}

/// Whether `url` points at this host (the token travels in clear otherwise).
pub fn is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else { return false };
    if host == "localhost" {
        return true;
    }
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    bare.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// Percent-encode one path segment (everything but unreserved characters).
fn escape_segment(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// ---------------------------------------------------------------- policy

/// Who may call a route (spec 8.5), the Python kit's order: deny list, allow
/// list (always allowed, even unregistered), registered, validator permit,
/// minimum stake.
#[derive(Debug, Clone)]
pub struct CallerPolicy {
    require_permit: bool,
    min_stake_tao: f64,
    allow: HashSet<String>,
    deny: HashSet<String>,
}

impl Default for CallerPolicy {
    /// The strict policy: registered, validator permit, no stake floor.
    fn default() -> Self {
        Self {
            require_permit: true,
            min_stake_tao: 0.0,
            allow: HashSet::new(),
            deny: HashSet::new(),
        }
    }
}

impl CallerPolicy {
    /// A policy; refuses a negative, NaN or infinite stake and a hotkey in
    /// both lists.
    pub fn new(
        require_permit: bool,
        min_stake_tao: f64,
        allow: impl IntoIterator<Item = String>,
        deny: impl IntoIterator<Item = String>,
    ) -> Result<Self, String> {
        if !(min_stake_tao >= 0.0 && min_stake_tao.is_finite()) {
            return Err("the minimum stake must be a finite number >= 0".into());
        }
        let deny: HashSet<String> = deny.into_iter().collect();
        let allow: HashSet<String> = allow.into_iter().collect();
        if !allow.is_disjoint(&deny) {
            return Err("a hotkey cannot be both allowed and denied".into());
        }
        Ok(Self { require_permit, min_stake_tao, allow, deny })
    }

    /// A 403 [`Error`] unless `hotkey` may call; else its neuron (`None` for
    /// an allow-listed unregistered hotkey).
    pub fn check<'s>(
        &self,
        hotkey: &str,
        snapshot: &'s Snapshot,
    ) -> Result<Option<&'s Neuron>, Error> {
        if self.deny.contains(hotkey) {
            return Err(Error::new("tw.forbidden_denied", ""));
        }
        let n = snapshot.by_hotkey(hotkey);
        if self.allow.contains(hotkey) {
            return Ok(n);
        }
        let n = n.ok_or_else(|| Error::new("tw.forbidden_not_registered", ""))?;
        if self.require_permit && !n.validator_permit {
            return Err(Error::new("tw.forbidden_not_validator", ""));
        }
        if self.min_stake_tao > 0.0 && n.total_stake_tao < self.min_stake_tao {
            return Err(Error::new("tw.forbidden_low_stake", ""));
        }
        Ok(Some(n))
    }
}

// ---------------------------------------------------------------- strict JSON

/// A JSON value with no object holding the same key twice, at any depth.
struct Strict(Value);

impl<'de> de::Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("JSON")
            }
            fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
                Number::from_f64(v)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("number"))
            }
            fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E>(self, v: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(v)))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut out = Vec::new();
                while let Some(Strict(v)) = seq.next_element()? {
                    out.push(v);
                }
                Ok(Strict(Value::Array(out)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut out = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    let Strict(v) = map.next_value()?;
                    if out.insert(key, v).is_some() {
                        return Err(de::Error::custom("duplicate key"));
                    }
                }
                Ok(Strict(Value::Object(out)))
            }
        }
        d.deserialize_any(V)
    }
}

fn bad(detail: &str) -> Error {
    Error::new(codes::INVALID_RESPONSE, format!("sidecar: {detail}"))
}

fn strict_object(body: &[u8]) -> Result<Map<String, Value>, Error> {
    match serde_json::from_slice::<Strict>(body) {
        Ok(Strict(Value::Object(o))) => Ok(o),
        Ok(_) => Err(bad("answer is not an object")),
        Err(_) => Err(bad("answer is not JSON")),
    }
}

fn int(v: Option<&Value>, max: u64) -> Option<u64> {
    v?.as_u64().filter(|n| *n <= max)
}

fn non_negative(v: Option<&Value>) -> Option<f64> {
    v?.as_f64().filter(|f| *f >= 0.0 && f.is_finite())
}

fn ss58(v: Option<&Value>) -> Option<String> {
    let s = v?.as_str()?;
    decode_ss58(s).map(|_| s.to_owned())
}

/// Parse a `/v1/metagraph` answer for `netuid`; any deviation from the
/// documented shape rejects the whole answer (`tw.invalid_response`).
pub fn parse_snapshot(body: &[u8], netuid: u16) -> Result<Snapshot, Error> {
    let o = strict_object(body)?;
    if int(o.get("netuid"), 65_535) != Some(u64::from(netuid)) {
        return Err(bad("snapshot for another netuid"));
    }
    let block = int(o.get("block"), u64::MAX).ok_or_else(|| bad("block"))?;
    let tempo = int(o.get("tempo"), 65_535).filter(|t| *t >= 1).ok_or_else(|| bad("tempo"))?;
    let age_s = non_negative(o.get("age_s")).ok_or_else(|| bad("age_s"))?;
    let raw = o.get("neurons").and_then(Value::as_array).filter(|a| a.len() <= MAX_NEURONS);
    let raw = raw.ok_or_else(|| bad("neurons"))?;
    let mut neurons = Vec::with_capacity(raw.len());
    let mut index = HashMap::new();
    let mut uids = HashSet::new();
    for r in raw {
        let m = r.as_object().ok_or_else(|| bad("neuron"))?;
        let uid = int(m.get("uid"), 65_535)
            .filter(|u| uids.insert(*u))
            .ok_or_else(|| bad("neuron uid"))?;
        let hotkey = ss58(m.get("hotkey"))
            .filter(|h| !index.contains_key(h))
            .ok_or_else(|| bad("neuron hotkey"))?;
        let permit = m
            .get("validator_permit")
            .and_then(Value::as_bool)
            .ok_or_else(|| bad("neuron validator_permit"))?;
        let stake =
            non_negative(m.get("total_stake_tao")).ok_or_else(|| bad("neuron total_stake_tao"))?;
        let axon = match m.get("axon") {
            Some(Value::Null) => None,
            Some(Value::String(s)) => Some(s.clone()),
            _ => return Err(bad("neuron axon")),
        };
        index.insert(hotkey.clone(), neurons.len());
        // uid <= 65 535 was checked above
        neurons.push(Neuron {
            uid: uid as u16,
            hotkey,
            validator_permit: permit,
            total_stake_tao: stake,
            axon,
        });
    }
    Ok(Snapshot { netuid, block, tempo: tempo as u16, age_s, neurons, index })
}

/// Parse a `/v1/caller` answer: allowed only for exactly `{"allowed": true}`.
pub fn parse_decision(body: &[u8]) -> Result<Decision, Error> {
    let o = strict_object(body)?;
    match (o.get("allowed"), o.get("code"), o.len()) {
        (Some(Value::Bool(true)), None, 1) => Ok(Decision::Allowed),
        (Some(Value::Bool(false)), Some(Value::String(c)), 2) => FORBIDDEN_CODES
            .iter()
            .find(|k| **k == c.as_str())
            .map(|k| Decision::Refused(k))
            .ok_or_else(|| bad("caller decision")),
        _ => Err(bad("caller decision")),
    }
}

/// Parse a `/v1/health` answer.
pub fn parse_health(body: &[u8]) -> Result<Health, Error> {
    let o = strict_object(body)?;
    let ok = o.get("ok").and_then(Value::as_bool).ok_or_else(|| bad("health ok"))?;
    let hotkey = ss58(o.get("hotkey")).ok_or_else(|| bad("health hotkey"))?;
    let netuid = int(o.get("netuid"), 65_535).ok_or_else(|| bad("health netuid"))? as u16;
    let block = match o.get("block") {
        Some(Value::Null) => None,
        v => Some(int(v, u64::MAX).ok_or_else(|| bad("health block"))?),
    };
    let metagraph_age_s = match o.get("metagraph_age_s") {
        Some(Value::Null) => None,
        v => Some(non_negative(v).ok_or_else(|| bad("health age"))?),
    };
    let stage = match o.get("stage").and_then(Value::as_str) {
        Some("fresh") => Stage::Fresh,
        Some("degraded") => Stage::Degraded,
        Some("known_callers_only") => Stage::KnownCallersOnly,
        _ => return Err(bad("health stage")),
    };
    Ok(Health { ok, hotkey, netuid, block, metagraph_age_s, stage })
}

// ---------------------------------------------------------------- client

/// Settings of a [`SidecarClient`].
#[derive(Clone)]
pub struct Config {
    /// The subnet (`TW_NETUID`).
    pub netuid: u16,
    /// Sidecar base URL; must be loopback unless `unsafe_allow_remote`.
    pub url: String,
    /// Token file (`TW_SIDECAR_TOKEN_FILE` when `None`), unless `token`.
    pub token_file: Option<std::path::PathBuf>,
    /// The token itself (tests; prefer `token_file`).
    pub token: Option<String>,
    /// Refuse a sidecar whose hotkey is not this one (the miner's).
    pub expected_hotkey: Option<String>,
    /// Caller policy (default: strict).
    pub policy: CallerPolicy,
    /// `TW_METAGRAPH_STRICT`: 503 for everyone past the max age.
    pub strict: bool,
    /// `TW_METAGRAPH_SOFT_AGE_S` (default `min(900 s, max / 2)`).
    pub soft_age: Option<Duration>,
    /// `TW_METAGRAPH_MAX_AGE_S` (default two tempos).
    pub max_age: Option<Duration>,
    /// Metagraph refresh (default 60 s).
    pub refresh: Duration,
    /// Per-call timeout (default 5 s).
    pub timeout: Duration,
    /// Allow a non-loopback URL (the token crosses a network in clear).
    pub unsafe_allow_remote: bool,
    /// Replaces the monotonic clock (tests).
    pub now: Option<Arc<dyn Fn() -> Instant + Send + Sync>>,
}

impl Config {
    /// Defaults for `netuid`.
    pub fn new(netuid: u16) -> Self {
        Self {
            netuid,
            url: DEFAULT_URL.into(),
            token_file: None,
            token: None,
            expected_hotkey: None,
            policy: CallerPolicy::default(),
            strict: false,
            soft_age: None,
            max_age: None,
            refresh: DEFAULT_REFRESH,
            timeout: DEFAULT_TIMEOUT,
            unsafe_allow_remote: false,
            now: None,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("netuid", &self.netuid)
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

struct Held {
    snapshot: Arc<Snapshot>,
    at: Instant,
}

#[derive(Default)]
struct State {
    held: Option<Held>,
    known: HashMap<String, Instant>,
    order: VecDeque<String>,
}

/// The sidecar client: cached metagraph, caller policy, serve-axon.
pub struct SidecarClient {
    cfg: Config,
    base: reqwest::Url,
    token: String,
    http: reqwest::Client,
    state: Mutex<State>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl fmt::Debug for SidecarClient {
    /// Never shows the token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SidecarClient({}, netuid {})",
            self.base.origin().ascii_serialization(),
            self.cfg.netuid
        )
    }
}

impl SidecarClient {
    /// A client; refuses a remote URL (without `unsafe_allow_remote`), a bad
    /// token or bad settings.
    pub fn new(mut cfg: Config) -> Result<Self, String> {
        let base =
            reqwest::Url::parse(&cfg.url).map_err(|_| "the sidecar URL is not a URL".to_owned())?;
        if !matches!(base.scheme(), "http" | "https") || base.host().is_none() {
            return Err("the sidecar URL must be http(s)://host:port".into());
        }
        if !is_loopback(&base) && !cfg.unsafe_allow_remote {
            return Err("the sidecar URL must be on loopback (127.0.0.0/8, ::1, localhost)".into());
        }
        let token = match cfg.token.take() {
            Some(t) => check_token(&t, "Config::token")?,
            None => {
                let path = cfg
                    .token_file
                    .clone()
                    .or_else(|| {
                        std::env::var_os("TW_SIDECAR_TOKEN_FILE")
                            .filter(|p| !p.is_empty())
                            .map(Into::into)
                    })
                    .ok_or_else(|| {
                        "set token_file (or TW_SIDECAR_TOKEN_FILE) or token".to_owned()
                    })?;
                read_token_file(&path)?
            }
        };
        if let (Some(soft), Some(max)) = (cfg.soft_age, cfg.max_age) {
            if soft >= max {
                return Err("soft_age must be below max_age".into());
            }
        }
        if cfg.refresh.is_zero() || cfg.timeout.is_zero() {
            return Err("refresh and timeout must be > 0".into());
        }
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self { cfg, base, token, http, state: Mutex::default(), task: Mutex::default() })
    }

    fn now(&self) -> Instant {
        self.cfg.now.as_ref().map_or_else(Instant::now, |f| f())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<(u16, Vec<u8>), Error> {
        let url = format!("{}{path}", self.base.origin().ascii_serialization());
        let mut req =
            self.http.request(method, url).bearer_auth(&self.token).timeout(self.cfg.timeout);
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b.to_string());
        }
        let net = |e: reqwest::Error| {
            if e.is_timeout() {
                Error::new(codes::TIMEOUT, "sidecar did not answer in time")
            } else {
                Error::new(codes::CONNECT_ERROR, "sidecar unreachable")
            }
        };
        let mut resp = req.send().await.map_err(net)?;
        let status = resp.status().as_u16();
        let mut data = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            if e.is_timeout() {
                Error::new(codes::TIMEOUT, "sidecar did not answer in time")
            } else {
                bad("answer could not be read")
            }
        })? {
            if data.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(Error::new(codes::RESPONSE_TOO_LARGE, "sidecar answer over the limit"));
            }
            data.extend_from_slice(&chunk);
        }
        Ok((status, data))
    }

    /// The sidecar's own `tw.*` code (Appendix A body with a matching status),
    /// else `tw.invalid_response`.
    fn error_of(status: u16, body: &[u8]) -> Error {
        let code = strict_object(body)
            .ok()
            .and_then(|o| o.get("error")?.get("code")?.as_str().map(str::to_owned));
        if let Some(code) = code {
            let e = Error::new(&code, "answered by the sidecar");
            if e.code == code && e.status == status {
                return e;
            }
        }
        bad(&format!("answered {status}"))
    }

    /// `GET /v1/health`.
    pub async fn health(&self) -> Result<Health, Error> {
        let (status, body) = self.call(reqwest::Method::GET, "/v1/health", None).await?;
        if status != 200 {
            return Err(Self::error_of(status, &body));
        }
        parse_health(&body)
    }

    /// `GET /v1/metagraph`: the snapshot, also stored for [`Self::check`].
    /// Only a newer snapshot replaces the held one and clears the known
    /// callers: a sidecar repeating its own stale snapshot changes nothing.
    pub async fn metagraph(&self) -> Result<Arc<Snapshot>, Error> {
        let path = format!("/v1/metagraph?netuid={}", self.cfg.netuid);
        let (status, body) = self.call(reqwest::Method::GET, &path, None).await?;
        if status != 200 {
            return Err(Self::error_of(status, &body));
        }
        let snapshot = Arc::new(parse_snapshot(&body, self.cfg.netuid)?);
        let now = self.now();
        let at = now.checked_sub(Duration::from_secs_f64(snapshot.age_s.min(1e9))).unwrap_or(now);
        let mut st = self.state();
        // The block decides; the derived time only when the chain stalls (the
        // answer's own delay, up to the timeout, must not make it look newer).
        let slack = self.cfg.timeout + Duration::from_secs(1);
        let newer = st
            .held
            .as_ref()
            .map_or(true, |h| snapshot.block > h.snapshot.block || at > h.at + slack);
        if newer {
            st.held = Some(Held { snapshot: Arc::clone(&snapshot), at });
            st.known.clear();
            st.order.clear();
        }
        Ok(snapshot)
    }

    /// `GET /v1/caller/{hotkey}`: the sidecar's own decision.
    pub async fn caller(&self, hotkey: &str) -> Result<Decision, Error> {
        let path = format!("/v1/caller/{}?netuid={}", escape_segment(hotkey), self.cfg.netuid);
        let (status, body) = self.call(reqwest::Method::GET, &path, None).await?;
        if status != 200 {
            return Err(Self::error_of(status, &body));
        }
        parse_decision(&body)
    }

    /// `POST /v1/serve-axon`: publish `ip:port` (and a TLS key, ADR-0011)
    /// for the sidecar's hotkey. Sent once: a chain write is never resent
    /// blindly. Returns the block hash.
    pub async fn serve_axon(
        &self,
        ip: &str,
        port: u16,
        tls_cert_hex: Option<&str>,
    ) -> Result<String, ServeAxonError> {
        let body = serde_json::json!({"netuid": self.cfg.netuid, "ip": ip, "port": port, "tls_cert_hex": tls_cert_hex});
        let (status, data) = self.call(reqwest::Method::POST, "/v1/serve-axon", Some(body)).await?;
        let o = strict_object(&data).ok();
        let field = |k: &str| o.as_ref().and_then(|o| o.get(k));
        let hash_ok = |h: &&str| {
            h.len() == 66
                && h.starts_with("0x")
                && h[2..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        };
        match status {
            200 => match (field("ok"), field("block_hash").and_then(Value::as_str).filter(hash_ok))
            {
                (Some(Value::Bool(true)), Some(h)) => Ok(h.to_owned()),
                _ => Err(bad("serve-axon answer").into()),
            },
            409 | 503 => match (field("ok"), field("code").and_then(Value::as_str)) {
                (Some(Value::Bool(false)), Some(code)) => Err(ServeAxonError::Chain {
                    code: code.to_owned(),
                    error_name: field("error_name").and_then(Value::as_str).map(str::to_owned),
                    remediation: field("remediation").and_then(Value::as_str).map(str::to_owned),
                }),
                _ => Err(Self::error_of(status, &data).into()),
            },
            _ => Err(Self::error_of(status, &data).into()),
        }
    }

    /// Check the sidecar (its netuid, and its hotkey when `expected_hotkey`
    /// is set), fetch the first snapshot, then refresh every `refresh`
    /// (±10%) in a background task until [`Self::stop`].
    pub async fn start(self: &Arc<Self>) -> Result<(), Error> {
        let h = self.health().await?;
        if h.netuid != self.cfg.netuid {
            return Err(bad("the sidecar follows another netuid"));
        }
        if self.cfg.expected_hotkey.as_deref().is_some_and(|k| k != h.hotkey) {
            return Err(bad("the sidecar's hotkey is not this miner's hotkey"));
        }
        self.metagraph().await?;
        let weak = Arc::downgrade(self);
        let refresh = self.cfg.refresh;
        let handle = tokio::spawn(async move {
            let mut seed = 0x9e37_79b9_7f4a_7c15_u64 ^ u64::from(std::process::id());
            loop {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let jitter = 0.9 + 0.2 * ((seed >> 11) as f64 / (1u64 << 53) as f64);
                tokio::time::sleep(refresh.mul_f64(jitter)).await;
                let Some(client) = weak.upgrade() else { return };
                let _ = client.metagraph().await; // a failure keeps the old snapshot; it keeps aging
            }
        });
        if let Some(old) = self.task.lock().unwrap_or_else(|p| p.into_inner()).replace(handle) {
            old.abort();
        }
        Ok(())
    }

    /// Stop the background refresh.
    pub fn stop(&self) {
        if let Some(t) = self.task.lock().unwrap_or_else(|p| p.into_inner()).take() {
            t.abort();
        }
    }

    /// The cached snapshot.
    pub fn snapshot(&self) -> Option<Arc<Snapshot>> {
        self.state().held.as_ref().map(|h| Arc::clone(&h.snapshot))
    }

    /// Age of the cached snapshot now.
    pub fn age(&self) -> Option<Duration> {
        let now = self.now();
        self.state().held.as_ref().map(|h| now.saturating_duration_since(h.at))
    }

    fn thresholds_of(&self, st: &State) -> (Duration, Duration) {
        let tempo = st.held.as_ref().map_or(360, |h| u32::from(h.snapshot.tempo));
        let max = self.cfg.max_age.unwrap_or(BLOCK_TIME * 2 * tempo);
        let soft = self.cfg.soft_age.unwrap_or_else(|| DEFAULT_SOFT_AGE.min(max / 2));
        (soft, max)
    }

    /// `(soft, max)` age in force (8.5.1; from the snapshot's tempo).
    pub fn thresholds(&self) -> (Duration, Duration) {
        self.thresholds_of(&self.state())
    }

    fn stage_of(&self, st: &State) -> Stage {
        let (soft, max) = self.thresholds_of(st);
        match st.held.as_ref().map(|h| self.now().saturating_duration_since(h.at)) {
            None => Stage::KnownCallersOnly,
            Some(age) if age > max => Stage::KnownCallersOnly,
            Some(age) if age >= soft => Stage::Degraded,
            Some(_) => Stage::Fresh,
        }
    }

    /// The current stage; no snapshot is [`Stage::KnownCallersOnly`].
    pub fn stage(&self) -> Stage {
        self.stage_of(&self.state())
    }

    /// Admit `hotkey` for `scope` (e.g. the route), or a 403 / 503
    /// `tw.metagraph_stale` [`Error`] (the Python `CallerGate.admit`).
    /// Returns its neuron.
    pub fn check(&self, hotkey: &str, scope: &str) -> Result<Option<Neuron>, Error> {
        if self.cfg.policy.deny.contains(hotkey) {
            return Err(Error::new("tw.forbidden_denied", ""));
        }
        let mut st = self.state();
        let key = format!("{scope}\n{hotkey}");
        if st.held.is_none() || self.stage_of(&st) == Stage::KnownCallersOnly {
            if self.cfg.strict || !st.known.contains_key(&key) {
                return Err(Error::new(codes::METAGRAPH_STALE, ""));
            }
            return Ok(st.held.as_ref().and_then(|h| h.snapshot.by_hotkey(hotkey).cloned()));
        }
        let snapshot = Arc::clone(&st.held.as_ref().expect("checked above").snapshot);
        let n = self.cfg.policy.check(hotkey, &snapshot)?.cloned();
        let now = self.now();
        if st.known.insert(key.clone(), now).is_none() {
            st.order.push_back(key);
            if st.order.len() > MAX_KNOWN_CALLERS {
                if let Some(old) = st.order.pop_front() {
                    st.known.remove(&old);
                }
            }
        }
        Ok(n)
    }

    /// The hook for `axum::MinerAuth::with_policy`, with the scope
    /// [`POLICY_SCOPE`] for every route (one policy guards them all).
    pub fn policy(self: &Arc<Self>) -> PolicyFn {
        let me = Arc::clone(self);
        Arc::new(move |caller, _path| me.check(&caller.hotkey, POLICY_SCOPE).map(|_| ()))
    }

    /// Entries in the known-callers set.
    pub fn known_callers(&self) -> usize {
        self.state().known.len()
    }
}

impl Drop for SidecarClient {
    fn drop(&mut self) {
        self.stop();
    }
}
