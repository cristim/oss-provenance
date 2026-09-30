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
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("oss-provenance/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self { endpoint, client })
    }

    pub fn scan(&self, id: &str, bytes: &[u8]) -> Result<ScanResult> {
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "input exceeds scanner's 16 MiB limit"
        );
        let wire_id = format!("source_{:x}", Sha256::digest(id.as_bytes()));
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
        let form = multipart::Form::new()
            .text("format", "plain")
            .part("file", multipart::Part::text(fp.wfp).file_name("scan.wfp"));
        let response = self
            .client
            .post(self.endpoint.clone())
            .multipart(form)
            .send()
            .context("SCANOSS request failed")?;
        ensure!(
            response.status().is_success(),
            "SCANOSS returned HTTP {}",
            response.status()
        );
        let mut body = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .context("reading SCANOSS response")?;
        ensure!(
            body.len() as u64 <= MAX_RESPONSE_BYTES,
            "SCANOSS response exceeds 4 MiB"
        );
        let candidates = parse_response(&body, &wire_id, fp.line_count)?;
        Ok(ScanResult {
            fingerprintable,
            candidates,
        })
    }
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
        let wire_id = format!("source_{:x}", Sha256::digest(b"src/private-name.rs"));
        let body = serde_json::json!({wire_id.clone():[{"id":"none"}]}).to_string();
        let source = b"fn example(value: u64) -> u64 { value + 17 }\n".repeat(30);
        let (result, sent) = request("200 OK", body.clone(), &source);
        assert!(result.unwrap().fingerprintable);
        assert!(sent.starts_with("POST /scan HTTP/1.1"));
        assert!(sent.contains("name=\"file\"; filename=\"scan.wfp\""));
        assert!(sent.contains(&wire_id));
        assert!(!sent.contains("private-name"));
        assert!(!sent.contains("fn example"));
        assert!(
            !request("200 OK", body.clone(), b"short")
                .0
                .unwrap()
                .fingerprintable
        );
        let binary = [source.as_slice(), &[0]].concat();
        assert!(!request("200 OK", body, &binary).0.unwrap().fingerprintable);
    }

    #[test]
    fn actual_http_errors_never_become_no_match() {
        for (status, body) in [
            ("503 Unavailable", "{}"),
            ("302 Found", "{}"),
            ("200 OK", "{}"),
            ("200 OK", "not-json"),
        ] {
            assert!(request(status, body.to_owned(), b"short").0.is_err());
        }
    }
}
