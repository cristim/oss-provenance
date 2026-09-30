// Adapted from SCANOSS scanoss.py's MIT-licensed winnowing.py.
// Copyright (c) 2021, SCANOSS. See LICENSE-NOTICES/scanoss-winnowing/.

use anyhow::{Result, ensure};
use md5::{Digest, Md5};
use std::collections::VecDeque;
use std::fmt::Write;

#[derive(Debug)]
pub struct Fingerprint {
    pub wfp: String,
    pub snippet_count: usize,
    pub line_count: usize,
}

/// Equivalent to the pinned Python reference with all_extensions=True, bin_file=False.
pub fn fingerprint(id: &str, bytes: &[u8]) -> Result<Fingerprint> {
    ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "fingerprint identity must be an opaque ASCII identifier"
    );
    let mut wfp = format!("file={:x},{},{}\n", Md5::digest(bytes), bytes.len(), id);
    if bytes.contains(&b'\n') || bytes.contains(&b'\r') {
        let mut normalized = Vec::with_capacity(bytes.len());
        let mut pure_crlf = true;
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
                normalized.push(b'\n');
                i += 2;
            } else {
                if bytes[i] == b'\r' || bytes[i] == b'\n' {
                    pure_crlf = false;
                }
                normalized.push(if bytes[i] == b'\r' { b'\n' } else { bytes[i] });
                i += 1;
            }
        }
        let opposite = if pure_crlf {
            normalized
        } else {
            let mut crlf = Vec::with_capacity(normalized.len());
            for byte in normalized {
                if byte == b'\n' {
                    crlf.push(b'\r');
                }
                crlf.push(byte);
            }
            crlf
        };
        writeln!(wfp, "fh2={:x}", Md5::digest(opposite))?;
    }

    let mut gram = VecDeque::with_capacity(30);
    let mut window = VecDeque::with_capacity(64);
    let mut last_hash = None;
    let mut last_line = 0;
    let mut line = 1;
    let mut snippet_count = 0;
    for &byte in bytes {
        if byte == b'\n' {
            line += 1;
        }
        if !byte.is_ascii_alphanumeric() {
            continue;
        }
        gram.push_back(byte.to_ascii_lowercase());
        if gram.len() == 30 {
            window.push_back(crc32c::crc32c(gram.make_contiguous()));
            if window.len() == 64 {
                let minimum = *window.iter().min().expect("full hash window");
                if last_hash != Some(minimum) {
                    if last_line != line {
                        if snippet_count > 0 {
                            wfp.push('\n');
                        }
                        write!(wfp, "{line}=")?;
                    } else {
                        wfp.push(',');
                    }
                    write!(wfp, "{:08x}", crc32c::crc32c(&minimum.to_le_bytes()))?;
                    last_hash = Some(minimum);
                    last_line = line;
                    snippet_count += 1;
                }
                window.pop_front();
            }
            gram.pop_front();
        }
    }
    if snippet_count > 0 {
        wfp.push('\n');
    }
    let line_count = if bytes.is_empty() {
        0
    } else {
        line - usize::from(bytes.last() == Some(&b'\n'))
    };
    Ok(Fingerprint {
        wfp,
        snippet_count,
        line_count,
    })
}
