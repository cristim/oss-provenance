use crate::fingerprint::fingerprint;
use anyhow::{Context, Result, bail, ensure};
use reqwest::blocking::{Client, multipart};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;

const MAX_RESPONSE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_WFP_BYTES: usize = 64 * 1024;

#[derive(Debug)]
pub struct ScannerFailure;

impl std::fmt::Display for ScannerFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SCANOSS verification unavailable; pause verification and inspect the cause without rewriting code or consuming repair budget")
    }
}

impl std::error::Error for ScannerFailure {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Candidate {
    pub id: String,
    pub local_ranges: Vec<(usize, usize)>,
    pub upstream_ranges: Vec<(usize, usize)>,
    pub url: Option<String>,
    pub file: Option<String>,
    pub file_hash: Option<String>,
    pub licenses: Vec<String>,
    pub raw: Value,
}

#[derive(Debug)]
pub struct ScanResult {
    pub fingerprintable: bool,
    pub candidates: Vec<Candidate>,
}

pub struct Scanner {
    endpoint: reqwest::Url,
    client: Client,
    timeout: Duration,
    cache: crate::cache::Cache,
}

impl Scanner {
    pub fn new(endpoint: &str, timeout_secs: u64) -> Result<Self> {
        let endpoint = reqwest::Url::parse(endpoint).context("invalid scanner endpoint")?;
        ensure!(
            endpoint.scheme() == "https",
            "scanner endpoint must use HTTPS"
        );
        Self::with_url(endpoint, timeout_secs)
    }

    fn with_url(endpoint: reqwest::Url, timeout_secs: u64) -> Result<Self> {
        ensure!(
            endpoint.host_str().is_some(),
            "scanner endpoint requires a host"
        );
        ensure!(
            endpoint.username().is_empty() && endpoint.password().is_none(),
            "scanner endpoint credentials are unsupported"
        );
        ensure!(
            endpoint.fragment().is_none(),
            "scanner endpoint must not contain a fragment"
        );
        ensure!(
            (1..=300).contains(&timeout_secs),
            "scanner timeout must be 1..300 seconds"
        );
        let timeout = Duration::from_secs(timeout_secs);
        let client = Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("oss-provenance/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            endpoint,
            client,
            timeout,
            cache: crate::cache::Cache::from_env()?,
        })
    }

    pub fn scan(&self, _id: &str, bytes: &[u8]) -> Result<ScanResult> {
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "input exceeds scanner's 16 MiB limit"
        );
        let content_hash = Sha256::digest(bytes);
        let wire_id = format!("source_{content_hash:x}");
        let fp = fingerprint(&wire_id, bytes)?;
        let fingerprintable =
            fp.snippet_count > 0 && std::str::from_utf8(bytes).is_ok() && !bytes.contains(&0);
        if bytes.is_empty() {
            return Ok(ScanResult {
                fingerprintable: false,
                candidates: Vec::new(),
            });
        }
        ensure!(
            fp.wfp.len() <= MAX_WFP_BYTES,
            "fingerprint exceeds 64 KiB; refusing a partial scan"
        );
        let key =
            crate::cache::key(&[b"scanner", self.endpoint.as_str().as_bytes(), &content_hash]);
        if let Some(body) =
            self.cache
                .load(&key, Some(Duration::from_secs(3600)), MAX_RESPONSE_BYTES)?
            && let Ok(candidates) = parse_response(&body, &wire_id, fp.line_count)
        {
            return Ok(ScanResult {
                fingerprintable,
                candidates,
            });
        }
        let body = self.request(&fp.wfp).context(ScannerFailure)?;
        let candidates = parse_response(&body, &wire_id, fp.line_count).context(ScannerFailure)?;
        self.cache.store(&key, &body)?;
        Ok(ScanResult {
            fingerprintable,
            candidates,
        })
    }

    fn request(&self, wfp: &str) -> Result<Vec<u8>> {
        let deadline = std::time::Instant::now() + self.timeout;
        for attempt in 0..3 {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            ensure!(
                !remaining.is_zero(),
                "SCANOSS total request timeout exhausted"
            );
            let form = multipart::Form::new().text("format", "plain").part(
                "file",
                multipart::Part::text(wfp.to_owned()).file_name("scan.wfp"),
            );
            let response = self
                .client
                .post(self.endpoint.clone())
                .timeout(remaining)
                .multipart(form)
                .send();
            let (error, delay) = match response {
                Err(error) => {
                    if !error.is_connect() && !error.is_timeout() {
                        return Err(error).context("SCANOSS request failed");
                    }
                    (
                        anyhow::Error::new(error).context("SCANOSS request failed"),
                        Duration::from_secs(1 << attempt),
                    )
                }
                Ok(response) => {
                    let status = response.status();
                    if status.is_success() {
                        let mut body = Vec::new();
                        match response.take(MAX_RESPONSE_BYTES + 1).read_to_end(&mut body) {
                            Ok(_) => {
                                ensure!(
                                    std::time::Instant::now() < deadline,
                                    "SCANOSS total request timeout exhausted while reading response"
                                );
                                ensure!(
                                    body.len() as u64 <= MAX_RESPONSE_BYTES,
                                    "SCANOSS response exceeds 4 MiB"
                                );
                                return Ok(body);
                            }
                            Err(error) => {
                                if !body_timeout(&error) {
                                    return Err(error).context("reading SCANOSS response");
                                }
                                (
                                    anyhow::Error::new(error)
                                        .context("reading SCANOSS response timed out"),
                                    Duration::from_secs(1 << attempt),
                                )
                            }
                        }
                    } else {
                        let description = match status.as_u16() {
                            429 => "rate limited",
                            502..=504 => "temporarily unavailable",
                            _ => "request rejected",
                        };
                        let error = anyhow::anyhow!("SCANOSS {description}: HTTP {status}");
                        if !matches!(status.as_u16(), 429 | 502 | 503 | 504) {
                            return Err(error);
                        }
                        let delay = retry_delay(response.headers(), attempt)
                            .with_context(|| format!("SCANOSS {description}: HTTP {status}"))?;
                        (error, delay)
                    }
                }
            };
            if attempt == 2 {
                return Err(error).context("SCANOSS failed after 3 attempts");
            }
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if delay >= remaining {
                return Err(error).context(format!("SCANOSS retry delay of at least {} seconds exceeds the remaining total timeout; no early retry was sent", delay.as_secs_f64()));
            }
            std::thread::sleep(delay);
        }
        unreachable!()
    }
}

fn retry_delay(headers: &reqwest::header::HeaderMap, attempt: u32) -> Result<Duration> {
    let fallback = Duration::from_secs(1 << attempt);
    let Some(header) = headers.get(reqwest::header::RETRY_AFTER) else {
        return Ok(fallback);
    };
    ensure!(
        headers.get_all(reqwest::header::RETRY_AFTER).iter().count() == 1,
        "SCANOSS returned multiple Retry-After headers; retry blocked"
    );
    let value = header
        .to_str()
        .context("SCANOSS returned an invalid Retry-After header; retry blocked")?
        .trim();
    let delay = if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        Duration::from_secs(
            value
                .parse::<u64>()
                .context("SCANOSS Retry-After delay is out of range; retry blocked")?,
        )
    } else {
        let date = httpdate::parse_http_date(value)
            .context("SCANOSS returned an invalid Retry-After header; retry blocked")?;
        date.duration_since(std::time::SystemTime::now())
            .unwrap_or(Duration::ZERO)
    };
    Ok(delay.max(fallback))
}

fn body_timeout(error: &(dyn std::error::Error + 'static)) -> bool {
    if let Some(error) = error.downcast_ref::<reqwest::Error>()
        && error.is_timeout()
    {
        return true;
    }
    if let Some(error) = error.downcast_ref::<std::io::Error>() {
        if matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ) {
            return true;
        }
        if let Some(inner) = error.get_ref()
            && body_timeout(inner)
        {
            return true;
        }
    }
    error.source().is_some_and(body_timeout)
}

fn parse_response(body: &[u8], expected_id: &str, line_count: usize) -> Result<Vec<Candidate>> {
    let response: UniqueJson = serde_json::from_slice(body).context("invalid SCANOSS JSON")?;
    let object = response
        .0
        .as_object()
        .context("SCANOSS response must be an object")?;
    ensure!(
        object.len() == 1 && object.contains_key(expected_id),
        "SCANOSS response does not account for exactly the requested file"
    );
    let matches = object[expected_id]
        .as_array()
        .context("SCANOSS matches must be an array")?;
    ensure!(
        !matches.is_empty(),
        "SCANOSS returned an empty match array without an explicit none result"
    );
    let mut seen = HashSet::new();
    let mut candidates = Vec::new();
    for raw in matches {
        ensure!(raw.is_object(), "SCANOSS match must be an object");
        ensure!(
            seen.insert(serde_json::to_string(raw)?),
            "duplicate SCANOSS match"
        );
        let id = raw
            .get("id")
            .and_then(Value::as_str)
            .context("SCANOSS match is missing its id")?;
        ensure!(
            raw.get("error").is_none() && raw.get("errors").is_none(),
            "SCANOSS returned a match with an error"
        );
        if id == "none" {
            ensure!(matches.len() == 1, "none cannot accompany another match");
            ensure!(
                [
                    "lines",
                    "oss_lines",
                    "matched",
                    "file",
                    "file_hash",
                    "url",
                    "licenses"
                ]
                .iter()
                .all(|field| raw.get(field).is_none()),
                "none result must not contain match evidence"
            );
            return Ok(Vec::new());
        }
        ensure!(
            id == "file" || id == "snippet",
            "unsupported SCANOSS match kind {id}"
        );
        let lines = raw
            .get("lines")
            .and_then(Value::as_str)
            .context("match is missing local ranges")?;
        let oss_lines = raw
            .get("oss_lines")
            .and_then(Value::as_str)
            .context("match is missing upstream ranges")?;
        let local_ranges = if id == "file" && lines == "all" {
            ensure!(line_count > 0, "file match for empty input");
            vec![(1, line_count)]
        } else {
            parse_ranges(lines, Some(line_count))?
        };
        let upstream_ranges = if id == "file" && oss_lines == "all" {
            Vec::new()
        } else {
            parse_ranges(oss_lines, None)?
        };
        let licenses = match raw.get("licenses") {
            None => Vec::new(),
            Some(value) => value
                .as_array()
                .context("licenses must be an array")?
                .iter()
                .map(|license| {
                    let name = license
                        .get("name")
                        .and_then(Value::as_str)
                        .context("license lacks a name")?;
                    ensure!(!name.trim().is_empty(), "license name is empty");
                    Ok(name.to_owned())
                })
                .collect::<Result<Vec<_>>>()?,
        };
        candidates.push(Candidate {
            id: id.to_owned(),
            local_ranges,
            upstream_ranges,
            url: optional_string(raw, "url")?,
            file: optional_string(raw, "file")?,
            file_hash: optional_string(raw, "file_hash")?,
            licenses,
            raw: raw.clone(),
        });
    }
    Ok(candidates)
}

fn optional_string(raw: &Value, field: &str) -> Result<Option<String>> {
    match raw.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(Some(value.clone())),
        _ => bail!("invalid SCANOSS {field}"),
    }
}

fn parse_ranges(value: &str, bound: Option<usize>) -> Result<Vec<(usize, usize)>> {
    let mut ranges = Vec::new();
    let mut previous_end = 0;
    for range in value.split(',') {
        let parts: Vec<_> = range.trim().split('-').collect();
        ensure!((1..=2).contains(&parts.len()), "invalid line range {range}");
        let number = |s: &str| -> Result<usize> {
            ensure!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()),
                "invalid line number"
            );
            s.parse().context("line number overflows")
        };
        let start = number(parts[0])?;
        let end = number(parts[parts.len() - 1])?;
        ensure!(
            start > previous_end && end >= start,
            "line ranges must be positive, ordered and disjoint"
        );
        ensure!(
            bound.is_none_or(|maximum| end <= maximum),
            "local range exceeds input line count"
        );
        ranges.push((start, end));
        previous_end = end;
    }
    Ok(ranges)
}

// serde_json::Value otherwise silently keeps the last occurrence of duplicate keys.
struct UniqueJson(Value);

impl<'de> Deserialize<'de> for UniqueJson {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UniqueJson;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("JSON without duplicate keys")
            }
            fn visit_bool<E: serde::de::Error>(
                self,
                v: bool,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, v: f64) -> std::result::Result<Self::Value, E> {
                serde_json::Number::from_f64(v)
                    .map(|n| UniqueJson(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }
            fn visit_str<E: serde::de::Error>(
                self,
                v: &str,
            ) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(v.into()))
            }
            fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Self::Value, E> {
                Ok(UniqueJson(Value::Null))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<UniqueJson>()? {
                    values.push(value.0);
                }
                Ok(UniqueJson(Value::Array(values)))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, value)) = map.next_entry::<String, UniqueJson>()? {
                    if values.insert(key.clone(), value.0).is_some() {
                        return Err(serde::de::Error::custom(format!(
                            "duplicate JSON key {key}"
                        )));
                    }
                }
                Ok(UniqueJson(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn accepts_explicit_none_and_valid_ranges() {
        assert!(
            parse_response(br#"{"x":[{"id":"none"}]}"#, "x", 10)
                .unwrap()
                .is_empty()
        );
        let body = br#"{"x":[{"id":"snippet","lines":"1-3,8,10","oss_lines":"20-22,28,30","licenses":[{"name":"MIT"}],"url":"https://example.org/source"}]}"#;
        let matches = parse_response(body, "x", 10).unwrap();
        assert_eq!(matches[0].local_ranges, vec![(1, 3), (8, 8), (10, 10)]);
        assert_eq!(
            matches[0].upstream_ranges,
            vec![(20, 22), (28, 28), (30, 30)]
        );
        assert_eq!(matches[0].licenses, vec!["MIT"]);
    }

    #[test]
    fn rejects_missing_partial_malformed_and_duplicate_results() {
        for body in [
            "{}",
            "[]",
            "{\"other\":[{\"id\":\"none\"}]}",
            r#"{"x":[{"id":"none"}],"extra":[]}"#,
            r#"{"x":[]}"#,
            r#"{"x":null}"#,
            r#"{"x":[{}]}"#,
            r#"{"x":[{"id":"unknown"}]}"#,
            r#"{"x":[{"id":"none"},{"id":"snippet"}]}"#,
            r#"{"x":[{"id":"none","lines":"1"}]}"#,
            r#"{"x":[{"id":"none","error":"partial scan"}]}"#,
            r#"{"x":[{"id":"none","file":"known.rs"}]}"#,
            r#"{"x":[{"id":"snippet","lines":"1"}]}"#,
            r#"{"x":[{"id":"file","lines":"all","oss_lines":"all","licenses":"MIT"}]}"#,
            r#"{"x":[{"id":"file","lines":"all","oss_lines":"all","licenses":[{}]}]}"#,
            r#"{"x":[{"id":"none"}],"x":[{"id":"none"}]}"#,
            r#"{"x":[{"id":"file","id":"none"}]}"#,
            r#"{"x":[{"id":"file","lines":"all","oss_lines":"all"},{"id":"file","lines":"all","oss_lines":"all"}]}"#,
        ] {
            assert!(
                parse_response(body.as_bytes(), "x", 10).is_err(),
                "accepted {body}"
            );
        }
        for lines in [
            "",
            "0",
            "11",
            "2-1",
            "1-11",
            "1,1",
            "2,1",
            "1-3,3-4",
            "1-2-3",
            "-1",
            "+1",
            "all",
            "1,",
            "184467440737095516160",
        ] {
            let body = serde_json::json!({"x":[{"id":"snippet","lines":lines,"oss_lines":"1"}]})
                .to_string();
            assert!(
                parse_response(body.as_bytes(), "x", 10).is_err(),
                "accepted {lines}"
            );
        }
    }

    #[test]
    fn recorded_public_hosted_match_is_accepted() {
        let line_count = fingerprint(
            "public_scanoss_reference",
            include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py"),
        )
        .unwrap()
        .line_count;
        let matches = parse_response(
            include_bytes!("../tests/fixtures/scanoss/hosted-public-response.json"),
            "public_scanoss_reference",
            line_count,
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "file");
        assert_eq!(matches[0].local_ranges, [(1, line_count)]);
        assert!(matches[0].upstream_ranges.is_empty());
        assert_eq!(matches[0].licenses, ["MIT"]);
        let snippet_matches = parse_response(
            include_bytes!("../tests/fixtures/scanoss/hosted-public-snippet-response.json"),
            "public_scanoss_reference_modified",
            line_count + 2,
        )
        .unwrap();
        assert_eq!(snippet_matches[0].id, "snippet");
        assert_eq!(snippet_matches[0].local_ranges, [(26, 647)]);
        assert_eq!(snippet_matches[0].upstream_ranges, [(26, 647)]);
    }

    fn request(status: &str, body: String, input: &[u8]) -> (Result<ScanResult>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/scan", listener.local_addr().unwrap());
        let status = status.to_owned();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut received = Vec::new();
            loop {
                let mut chunk = [0; 4096];
                let length = stream.read(&mut chunk).unwrap();
                assert!(length > 0);
                received.extend_from_slice(&chunk[..length]);
                if let Some(end) = received.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&received[..end]).to_lowercase();
                    let content_length: usize = headers
                        .lines()
                        .find_map(|line| line.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if received.len() >= end + 4 + content_length {
                        break;
                    }
                }
            }
            write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            String::from_utf8(received).unwrap()
        });
        let scanner = Scanner::with_url(reqwest::Url::parse(&endpoint).unwrap(), 5).unwrap();
        let result = scanner.scan("src/private-name.rs", input);
        (result, server.join().unwrap())
    }

    #[test]
    fn actual_http_multipart_preserves_identity_and_reports_coverage() {
        let source = b"fn example(value: u64) -> u64 { value + 17 }\n".repeat(30);
        let binary = [source.as_slice(), &[0]].concat();
        for (input, fingerprintable) in [
            (source.as_slice(), true),
            (b"short".as_slice(), false),
            (binary.as_slice(), false),
        ] {
            let wire_id = format!("source_{:x}", Sha256::digest(input));
            let body = serde_json::json!({wire_id.clone():[{"id":"none"}]}).to_string();
            let (result, sent) = request("200 OK", body, input);
            assert_eq!(result.unwrap().fingerprintable, fingerprintable);
            assert!(sent.starts_with("POST /scan HTTP/1.1"));
            assert!(sent.contains("name=\"file\"; filename=\"scan.wfp\""));
            assert!(sent.contains(&wire_id));
            assert!(!sent.contains("private-name"));
            assert!(!sent.contains("fn example"));
        }
    }

    #[test]
    fn actual_http_errors_never_become_no_match() {
        for (status, body) in [
            ("503 Unavailable", "{}"),
            ("302 Found", "{}"),
            ("200 OK", "{}"),
            ("200 OK", "not-json"),
        ] {
            let error = request(status, body.to_owned(), b"short").0.unwrap_err();
            assert!(error.downcast_ref::<ScannerFailure>().is_some());
        }
    }
}

#[cfg(test)]
mod cache_retry_tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    fn no_match(input: &[u8]) -> String {
        format!(
            r#"{{"source_{:x}":[{{"id":"none"}}]}}"#,
            Sha256::digest(input)
        )
    }

    struct Server {
        done: std::sync::mpsc::Sender<()>,
        thread: thread::JoinHandle<Vec<String>>,
    }

    impl Server {
        fn join(self) -> thread::Result<Vec<String>> {
            let _ = self.done.send(());
            self.thread.join()
        }
    }

    fn server(responses: Vec<String>) -> (reqwest::Url, Server) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/scan", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        listener.set_nonblocking(true).unwrap();
        let (done, stopped) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(12);
            let mut requests = Vec::new();
            loop {
                let mut stream = loop {
                    if stopped.try_recv() != Err(std::sync::mpsc::TryRecvError::Empty) {
                        return requests;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "missing expected HTTP request"
                            );
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let count = stream.read(&mut buf).unwrap();
                    assert!(count > 0, "truncated request");
                    request.extend_from_slice(&buf[..count]);
                    if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                        let header = String::from_utf8_lossy(&request[..end]);
                        let length = header
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                let reply = responses
                    .get(requests.len())
                    .cloned()
                    .unwrap_or_else(|| response("500 Unexpected Request", "", ""));
                requests.push(String::from_utf8(request).unwrap());
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        (
            endpoint,
            Server {
                done,
                thread: handle,
            },
        )
    }

    fn response(status: &str, headers: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
            body.len()
        )
    }

    fn scanner(endpoint: reqwest::Url, root: &std::path::Path) -> Scanner {
        let mut scanner = Scanner::with_url(endpoint, 10).unwrap();
        scanner.cache = crate::cache::Cache::at(root.to_owned()).unwrap();
        scanner
    }

    #[test]
    fn fixture_reads_fragmented_request_bodies() {
        let (endpoint, requests) = server(vec![response("200 OK", "", "")]);
        let mut stream =
            std::net::TcpStream::connect(("127.0.0.1", endpoint.port().unwrap())).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .write_all(b"POST /scan HTTP/1.1\r\nContent-Length: 4\r\n\r\nab")
            .unwrap();
        thread::sleep(Duration::from_millis(100));
        stream.write_all(b"cd").unwrap();
        let mut reply = String::new();
        stream.read_to_string(&mut reply).unwrap();
        assert!(reply.starts_with("HTTP/1.1 200 OK"));
        let requests = requests.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].ends_with("\r\n\r\nabcd"));
    }

    #[test]
    fn cached_response_reuses_content_after_rename_without_refresh() {
        let input = b"source bytes for rename";
        let (endpoint, requests) = server(vec![response("200 OK", "", &no_match(input))]);
        let directory = tempfile::tempdir().unwrap();
        let scanner = scanner(endpoint, directory.path());
        scanner.scan("private/old.rs", input).unwrap();
        let path = std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let mut before = std::fs::read(&path).unwrap();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - 10;
        before[10..18].copy_from_slice(&stamp.to_be_bytes());
        std::fs::write(&path, &before).unwrap();
        scanner.scan("private/new.rs", input).unwrap();
        assert_eq!(std::fs::read(path).unwrap(), before);
        let requests = requests.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].contains("private/"));
        assert!(requests[0].contains(&format!("source_{:x}", Sha256::digest(input))));
    }

    #[test]
    fn changed_content_and_endpoint_require_requests() {
        let first = b"first source";
        let second = b"second source";
        let (endpoint, requests) = server(vec![
            response("200 OK", "", &no_match(first)),
            response("200 OK", "", &no_match(second)),
        ]);
        let directory = tempfile::tempdir().unwrap();
        let scanner_a = scanner(endpoint, directory.path());
        scanner_a.scan("same.rs", first).unwrap();
        scanner_a.scan("same.rs", second).unwrap();
        assert_eq!(requests.join().unwrap().len(), 2);
        let (endpoint, requests) = server(vec![response("200 OK", "", &no_match(first))]);
        scanner(endpoint, directory.path())
            .scan("same.rs", first)
            .unwrap();
        assert_eq!(requests.join().unwrap().len(), 1);
    }

    #[test]
    fn corrupt_expired_and_invalid_json_cache_require_fresh_requests() {
        let input = b"cache invalidation";
        let (endpoint, requests) = server(vec![response("200 OK", "", &no_match(input)); 4]);
        let directory = tempfile::tempdir().unwrap();
        let scanner = scanner(endpoint, directory.path());
        scanner.scan("source.rs", input).unwrap();
        let path = std::fs::read_dir(directory.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(&path, b"broken record").unwrap();
        scanner.scan("source.rs", input).unwrap();
        let mut record = std::fs::read(&path).unwrap();
        record[10..18].copy_from_slice(&0_u64.to_be_bytes());
        std::fs::write(&path, record).unwrap();
        scanner.scan("source.rs", input).unwrap();
        let key = path.file_name().unwrap().to_str().unwrap();
        scanner.cache.store(key, b"not JSON").unwrap();
        scanner.scan("source.rs", input).unwrap();
        assert_eq!(requests.join().unwrap().len(), 4);
    }

    #[test]
    fn transient_statuses_retry_and_success_is_cached() {
        let input = b"retry source";
        let (endpoint, requests) = server(vec![
            response("429 Too Many Requests", "Retry-After: 0\r\n", ""),
            response("503 Service Unavailable", "", ""),
            response("200 OK", "", &no_match(input)),
        ]);
        let directory = tempfile::tempdir().unwrap();
        let scanner = scanner(endpoint, directory.path());
        scanner.scan("source.rs", input).unwrap();
        scanner.scan("renamed.rs", input).unwrap();
        assert_eq!(requests.join().unwrap().len(), 3);
    }

    #[test]
    fn malformed_and_long_retry_after_block_without_an_early_retry() {
        for header in ["invalid", "100", "18446744073709551616"] {
            let (endpoint, requests) = server(vec![response(
                "429 Too Many Requests",
                &format!("Retry-After: {header}\r\n"),
                "",
            )]);
            let directory = tempfile::tempdir().unwrap();
            let started = std::time::Instant::now();
            let error = scanner(endpoint, directory.path())
                .scan("source.rs", b"input")
                .unwrap_err();
            assert!(format!("{error:#}").contains("retry"));
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(requests.join().unwrap().len(), 1);
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn malformed_live_response_is_never_cached() {
        let (endpoint, requests) = server(vec![response("200 OK", "", "not JSON"); 2]);
        let directory = tempfile::tempdir().unwrap();
        let scanner = scanner(endpoint, directory.path());
        for _ in 0..2 {
            let error = scanner.scan("source.rs", b"input").unwrap_err();
            assert!(error.downcast_ref::<ScannerFailure>().is_some());
        }
        assert_eq!(requests.join().unwrap().len(), 2);
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn retry_after_http_date_respects_server_minimum() {
        let mut headers = reqwest::header::HeaderMap::new();
        let date = std::time::SystemTime::now() + Duration::from_secs(30);
        headers.insert(
            reqwest::header::RETRY_AFTER,
            httpdate::fmt_http_date(date).parse().unwrap(),
        );
        assert!(retry_delay(&headers, 0).unwrap() >= Duration::from_secs(28));
        headers.insert(reqwest::header::RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(retry_delay(&headers, 0).unwrap(), Duration::from_secs(2));
    }

    #[test]
    fn retries_share_one_total_timeout() {
        let (endpoint, requests) = server(vec![response("503 Service Unavailable", "", ""); 2]);
        let directory = tempfile::tempdir().unwrap();
        let mut scanner = scanner(endpoint, directory.path());
        scanner.timeout = Duration::from_secs(2);
        let started = std::time::Instant::now();
        let error = scanner.scan("source.rs", b"input").unwrap_err();
        assert!(format!("{error:#}").contains("remaining total timeout"));
        assert!(started.elapsed() >= Duration::from_secs(1));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(requests.join().unwrap().len(), 2);
    }

    #[test]
    fn stalled_response_body_is_bounded_by_total_timeout() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}/scan", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut buffer = [0; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).unwrap();
                assert!(count > 0);
                request.extend_from_slice(&buffer[..count]);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                .unwrap();
            thread::sleep(Duration::from_secs(3));
        });
        let directory = tempfile::tempdir().unwrap();
        let mut scanner = scanner(endpoint, directory.path());
        scanner.timeout = Duration::from_secs(1);
        let started = std::time::Instant::now();
        let error = scanner.scan("source.rs", b"input").unwrap_err();
        assert!(
            format!("{error:#}").contains("timeout") || format!("{error:#}").contains("timed out")
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        server.join().unwrap();
    }

    #[test]
    fn permanent_statuses_are_not_retried() {
        for status in ["400 Bad Request", "403 Forbidden", "302 Found"] {
            let (endpoint, requests) = server(vec![response(status, "", "")]);
            let directory = tempfile::tempdir().unwrap();
            assert!(
                scanner(endpoint, directory.path())
                    .scan("source.rs", b"input")
                    .is_err()
            );
            assert_eq!(requests.join().unwrap().len(), 1);
        }
    }

    #[test]
    fn retry_exhaustion_distinguishes_rate_limit_from_outage() {
        for (status, expected) in [
            ("429 Too Many Requests", "rate limited"),
            ("503 Service Unavailable", "temporarily unavailable"),
        ] {
            let (endpoint, requests) = server(vec![response(status, "", ""); 3]);
            let directory = tempfile::tempdir().unwrap();
            let error = scanner(endpoint, directory.path())
                .scan("source.rs", b"input")
                .unwrap_err();
            let error = format!("{error:#}");
            assert!(error.contains(expected));
            assert!(error.contains("failed after 3 attempts"));
            assert!(error.contains("pause verification"));
            assert!(error.contains("without rewriting code or consuming repair budget"));
            assert_eq!(requests.join().unwrap().len(), 3);
            assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
        }
    }

    #[test]
    fn body_timeout_classifies_nested_io_errors_without_text_matching() {
        let timeout =
            std::io::Error::other(std::io::Error::new(std::io::ErrorKind::TimedOut, "elapsed"));
        assert!(body_timeout(&timeout));
        assert!(!body_timeout(&std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "timeout"
        )));
    }
}
