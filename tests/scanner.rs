use oss_provenance::fingerprint::fingerprint;
use oss_provenance::scanner::Scanner;
use serde_json::Value;

#[test]
fn native_fingerprints_match_the_pinned_official_python_oracle() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/scanoss/oracle.json")).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let id = case["id"].as_str().unwrap();
        let hex = case["bytes_hex"].as_str().unwrap();
        let bytes: Vec<_> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let actual = fingerprint(id, &bytes).unwrap();
        let expected = case["wfp"].as_str().unwrap();
        assert_eq!(actual.wfp, expected, "oracle mismatch: {id}");
        let expected_count: usize = expected
            .lines()
            .filter(|line| line.as_bytes()[0].is_ascii_digit())
            .map(|line| line.split_once('=').unwrap().1.split(',').count())
            .sum();
        assert_eq!(actual.snippet_count, expected_count, "snippet count: {id}");
        let expected_lines = bytes.iter().filter(|&&b| b == b'\n').count()
            + usize::from(!bytes.is_empty() && bytes.last() != Some(&b'\n'));
        assert_eq!(actual.line_count, expected_lines, "line count: {id}");
    }
}

#[test]
fn fingerprint_rejects_path_and_protocol_injection() {
    for id in ["", "src/private.rs", "secret\nfile=x", "a,b", "..", "a\\b"] {
        assert!(fingerprint(id, b"content").is_err());
    }
}

#[test]
fn production_transport_requires_https_and_bounded_timeouts() {
    for endpoint in [
        "http://localhost/scan",
        "http://127.0.0.1/scan",
        "file:///tmp/x",
        "https://user:secret@example.org/scan",
        "https://example.org/scan#fragment",
    ] {
        assert!(Scanner::new(endpoint, 10).is_err());
    }
    assert!(Scanner::new("https://example.org/scan", 0).is_err());
    assert!(Scanner::new("https://example.org/scan", 301).is_err());
}

#[test]
#[ignore = "explicit opt-in: uploads only the bundled public MIT SCANOSS reference fingerprint"]
fn live_public_upstream_fixture_matches() {
    let bytes = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py");
    let result = Scanner::new("https://api.osskb.org/scan/direct", 60)
        .unwrap()
        .scan("public_scanoss_reference", bytes)
        .unwrap();
    assert!(result.fingerprintable);
    assert!(
        result
            .candidates
            .iter()
            .any(|candidate| candidate.url.as_deref()
                == Some("https://github.com/scanoss/scanoss.py"))
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&result.candidates).unwrap()
    );
}

#[test]
#[ignore = "explicit opt-in: uploads only a modified public MIT SCANOSS reference fingerprint"]
fn live_public_upstream_snippet_matches() {
    let mut bytes = include_bytes!("../LICENSE-NOTICES/scanoss-winnowing/winnowing.py").to_vec();
    bytes.extend_from_slice(b"\n\n");
    let result = Scanner::new("https://api.osskb.org/scan/direct", 60)
        .unwrap()
        .scan("public_scanoss_reference_modified", &bytes)
        .unwrap();
    assert!(result.fingerprintable);
    assert!(
        result
            .candidates
            .iter()
            .any(|candidate| candidate.id == "snippet"
                && candidate.url.as_deref() == Some("https://github.com/scanoss/scanoss.py"))
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&result.candidates).unwrap()
    );
}
