use anyhow::Result;
use atomium_core::{
    encode_agy_oauth_for_keychain, read_projected_oauth_file_confined, EncryptedVault,
};
use atomium_protocol::TaskEventPayload;
use base64::Engine;
use std::path::Path;
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};

use crate::state::DaemonState;

const MAX_LOG_LINE_BYTES: usize = 8 * 1024;
const TRUNCATED_CHILD_LINE: &str = "[atomium] log line truncated after 8192 bytes";
pub(crate) const MAX_LOG_STREAM_BYTES: usize = 1024 * 1024;

fn collect_secret_fragments(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                collect_secret_fragments(item, out);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, item) in map {
                if atomium_core::credential_key_is_sensitive(key) {
                    if let Some(secret) = item.as_str().filter(|secret| secret.len() >= 16) {
                        out.push(secret.to_owned());
                    }
                }
                collect_secret_fragments(item, out);
            }
        }
        _ => {}
    }
}

fn redaction_replacement(secret: &str) -> String {
    let digest = EncryptedVault::digest_hex(secret.as_bytes());
    format!("<redacted:sha256:{}>", &digest[..12])
}

fn token_redaction_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(
            r"(sk-[A-Za-z0-9_-]{20,}|ya29\.[\w-]+|AIza[\w-]{35}|Bearer\s+\S+|\beyJ[\w-]*\.[\w-]+\.[\w-]+\b)",
        )
        .expect("valid token redaction regex")
    })
}

fn base64_candidate_pattern() -> &'static regex::Regex {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(r"\b[A-Za-z0-9+/]{40,}={0,2}\b").expect("valid base64 candidate regex")
    })
}

fn shannon_entropy_bits_per_byte(text: &str) -> f64 {
    let mut counts = [0usize; 256];
    for byte in text.as_bytes() {
        counts[*byte as usize] += 1;
    }
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[derive(Clone, Debug, Default)]
pub(crate) struct SecretRedactor {
    fragments: Vec<String>,
}

impl SecretRedactor {
    pub(crate) fn from_secret_bytes(bytes: &[u8]) -> Self {
        let mut redactor = Self::default();
        redactor.add_secret_bytes(bytes);
        redactor
    }

    pub(crate) fn add_secret_bytes(&mut self, bytes: &[u8]) {
        let mut new_fragments = Vec::new();
        if let Ok(text) = std::str::from_utf8(bytes) {
            if text.len() >= 16 {
                new_fragments.push(text.to_string());
            }
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(text) {
                collect_secret_fragments(&json, &mut new_fragments);
            }
        }
        // Redact common base64 carrying forms as credential material too, not only literal plaintext.
        for fragment in new_fragments.clone() {
            if fragment.len() >= 16 {
                new_fragments.push(base64::engine::general_purpose::STANDARD.encode(&fragment));
            }
        }
        self.fragments.extend(new_fragments);
        self.fragments.sort_unstable_by(|left, right| {
            right.len().cmp(&left.len()).then_with(|| left.cmp(right))
        });
        self.fragments.dedup();
    }

    pub(crate) fn redact(&self, line: &str) -> String {
        let mut redacted: String = line
            .chars()
            .map(|c| {
                if c.is_control() && c != '\t' {
                    '\u{FFFD}'
                } else {
                    c
                }
            })
            .collect();
        let mut ranges: Vec<(usize, usize)> = token_redaction_pattern()
            .find_iter(&redacted)
            .map(|found| (found.start(), found.end()))
            .collect();
        for fragment in &self.fragments {
            ranges.extend(
                redacted
                    .match_indices(fragment)
                    .map(|(start, _)| (start, start + fragment.len())),
            );
        }
        ranges.extend(
            base64_candidate_pattern()
                .find_iter(&redacted)
                .filter(|found| shannon_entropy_bits_per_byte(found.as_str()) >= 4.2)
                .map(|found| (found.start(), found.end())),
        );
        ranges.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::new();
        for (start, end) in ranges {
            if let Some(last) = merged.last_mut().filter(|last| start < last.1) {
                last.1 = last.1.max(end);
            } else {
                merged.push((start, end));
            }
        }
        for (start, end) in merged.into_iter().rev() {
            let replacement = redaction_replacement(&redacted[start..end]);
            redacted.replace_range(start..end, &replacement);
        }
        if redacted.len() > MAX_LOG_LINE_BYTES {
            let mut end = MAX_LOG_LINE_BYTES;
            while !redacted.is_char_boundary(end) {
                end -= 1;
            }
            redacted.truncate(end);
            redacted.push_str("…[truncated]");
        }
        redacted
    }

    pub(crate) fn redact_args(&self, args: &[String]) -> Vec<String> {
        fn sensitive_flag(flag: &str) -> bool {
            let normalized = flag
                .trim_start_matches('-')
                .replace('_', "-")
                .to_ascii_lowercase();
            matches!(
                normalized.as_str(),
                "token"
                    | "api-key"
                    | "apikey"
                    | "password"
                    | "secret"
                    | "access-token"
                    | "refresh-token"
                    | "id-token"
                    | "client-secret"
                    | "auth-token"
                    | "bearer-token"
            )
        }

        let mut out = Vec::with_capacity(args.len());
        let mut redact_next = false;
        for arg in args {
            if redact_next {
                out.push(redaction_replacement(arg));
                redact_next = false;
                continue;
            }
            if let Some((flag, value)) = arg.split_once('=') {
                if sensitive_flag(flag) {
                    out.push(format!("{}={}", flag, redaction_replacement(value)));
                    continue;
                }
            }
            if sensitive_flag(arg) {
                out.push(arg.clone());
                redact_next = true;
                continue;
            }
            out.push(self.redact(arg));
        }
        out
    }
}

#[derive(Default)]
pub(crate) struct RunLogRedactor {
    pub(crate) redactor: SecretRedactor,
    projection_stamp: Option<(u64, u64, u64, i64, i64, i64, i64)>,
    pub(crate) digest_only: bool,
}

impl RunLogRedactor {
    pub(crate) fn new(redactor: SecretRedactor, digest_only: bool) -> Self {
        Self {
            redactor,
            projection_stamp: None,
            digest_only,
        }
    }

    pub(crate) fn refresh(&mut self, run_home: &Path, relative_path: Option<&str>) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let Some(relative_path) = relative_path else {
            return Ok(());
        };
        let meta = std::fs::symlink_metadata(run_home.join(relative_path))?;
        let stamp = (
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime(),
            meta.mtime_nsec(),
            meta.ctime(),
            meta.ctime_nsec(),
        );
        if self.projection_stamp != Some(stamp) {
            if let Some(bytes) = read_projected_oauth_file_confined(run_home, relative_path)? {
                let value = serde_json::from_slice(&bytes)?;
                if atomium_core::validate_credential_secret_lengths(&value).is_err() {
                    // A later valid projection cannot prove the child forgot the rejected value.
                    self.digest_only = true;
                } else {
                    self.redactor.add_secret_bytes(&bytes);
                }
            }
            self.projection_stamp = Some(stamp);
        }
        Ok(())
    }
}

pub(crate) fn oauth_log_redactor(decoded: &[u8], stored: &[u8]) -> SecretRedactor {
    let mut redactor = SecretRedactor::from_secret_bytes(decoded);
    redactor.add_secret_bytes(stored);
    let keychain_wrapped = encode_agy_oauth_for_keychain(decoded);
    redactor.add_secret_bytes(&keychain_wrapped);
    redactor
}

pub(crate) enum ChildLogLine {
    Text(String),
    Truncated,
}

impl ChildLogLine {
    pub(crate) fn into_audit_text(self, digest_only: bool) -> String {
        match self {
            Self::Text(text) if digest_only => redaction_replacement(&text),
            Self::Text(text) => text,
            // This records discarded input, so it must not look like a digest of that input.
            Self::Truncated => TRUNCATED_CHILD_LINE.into(),
        }
    }
}

pub(crate) async fn read_bounded_child_line<R>(
    reader: &mut BufReader<R>,
) -> Result<Option<ChildLogLine>>
where
    R: AsyncRead + Unpin,
{
    // One additional byte distinguishes an exact-size CRLF line from oversized content.
    let mut out = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return if oversized || out.len() > MAX_LOG_LINE_BYTES {
                Ok(Some(ChildLogLine::Truncated))
            } else if out.is_empty() {
                Ok(None)
            } else {
                Ok(Some(ChildLogLine::Text(
                    String::from_utf8_lossy(&out).into_owned(),
                )))
            };
        }

        let newline_pos = available.iter().position(|b| *b == b'\n');
        let content_len = newline_pos.unwrap_or(available.len());
        let take = content_len + usize::from(newline_pos.is_some());
        if !oversized {
            if out.len() + content_len > MAX_LOG_LINE_BYTES + 1 {
                oversized = true;
                out.clear();
            } else {
                out.extend_from_slice(&available[..content_len]);
            }
        }
        reader.consume(take);

        if newline_pos.is_some() {
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            if oversized || out.len() > MAX_LOG_LINE_BYTES {
                return Ok(Some(ChildLogLine::Truncated));
            }
            return Ok(Some(ChildLogLine::Text(
                String::from_utf8_lossy(&out).into_owned(),
            )));
        }
    }
}

pub(crate) fn emit_bounded_log_line(
    state: &DaemonState,
    run_id: &str,
    stream: &str,
    line: &str,
    redactor: &SecretRedactor,
    emitted_bytes: &mut usize,
    truncation_notified: &mut bool,
) {
    if *truncation_notified {
        return;
    }
    let redacted = redactor.redact(line);
    let prospective = emitted_bytes.saturating_add(redacted.len().saturating_add(1));
    if prospective > MAX_LOG_STREAM_BYTES {
        *truncation_notified = true;
        let _ = state.emit_event(
            run_id,
            &TaskEventPayload::LogLine {
                stream: stream.into(),
                line: format!(
                    "[atomium] {stream} log truncated after {MAX_LOG_STREAM_BYTES} bytes"
                ),
            },
        );
        return;
    }
    *emitted_bytes = prospective;
    let _ = state.emit_event(
        run_id,
        &TaskEventPayload::LogLine {
            stream: stream.into(),
            line: redacted,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn bounded_child_lines_keep_exact_boundaries_and_consume_complete_lines() {
        for capacity in [1, 7, MAX_LOG_LINE_BYTES] {
            for len in [
                0,
                MAX_LOG_LINE_BYTES - 1,
                MAX_LOG_LINE_BYTES,
                MAX_LOG_LINE_BYTES + 1,
                65536,
            ] {
                for ending in ["\n", "\r\n", ""] {
                    let content = "x".repeat(len);
                    let input = if ending.is_empty() {
                        content.clone()
                    } else {
                        format!("{content}{ending}next\r\n")
                    };
                    let mut reader = BufReader::with_capacity(capacity, input.as_bytes());
                    let line = read_bounded_child_line(&mut reader).await.unwrap();
                    if len > MAX_LOG_LINE_BYTES {
                        assert!(matches!(line, Some(ChildLogLine::Truncated)));
                    } else if len == 0 && ending.is_empty() {
                        assert!(line.is_none());
                    } else {
                        assert!(matches!(line, Some(ChildLogLine::Text(text)) if text == content));
                    }
                    if !ending.is_empty() {
                        let next = read_bounded_child_line(&mut reader).await.unwrap();
                        assert!(matches!(next, Some(ChildLogLine::Text(text)) if text == "next"));
                    }
                    assert!(read_bounded_child_line(&mut reader)
                        .await
                        .unwrap()
                        .is_none());
                }
            }
        }
    }

    #[tokio::test]
    async fn bounded_child_line_drains_large_generated_stream_without_retaining_fragments() {
        let source = tokio::io::repeat(b'x').take(16 * 1024 * 1024);
        let mut reader = BufReader::with_capacity(1024, source);
        assert!(matches!(
            read_bounded_child_line(&mut reader).await.unwrap(),
            Some(ChildLogLine::Truncated)
        ));
        assert!(read_bounded_child_line(&mut reader)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn repeated_observations_keep_each_secret_fragment_once() {
        let raw = serde_json::to_vec(&serde_json::json!({
            "access_token": (["opaque-first-", "abcdefghijklmnop"].concat()),
            "refresh_token": (["opaque-other-", "qrstuvwxyzabcdef"].concat())
        }))
        .unwrap();
        let mut redactor = SecretRedactor::from_secret_bytes(&raw);
        let count = redactor.fragments.len();
        redactor.add_secret_bytes(&raw);
        assert_eq!(redactor.fragments.len(), count);
    }

    #[test]
    fn agy_leaf_secrets_do_not_disable_bearer_pattern() {
        let raw = serde_json::json!({"auth_method":"consumer","id_token_email":"mock@example.test","token":{"access_token":"ya29.syntheticinitialaccess","refresh_token":"1//syntheticrefreshmaterial","token_type":"Bearer","expiry":"2026-11-26T00:00:00Z"}});
        let redactor = SecretRedactor::from_secret_bytes(&serde_json::to_vec(&raw).unwrap());
        assert!(redactor
            .fragments
            .iter()
            .all(|fragment| fragment.len() >= 16));
        let unrelated = format!("{}{}", "syntheticnew", "bearercredential");
        assert!(!redactor
            .redact(&format!("Authorization: Bearer {unrelated}"))
            .contains(&unrelated));
        assert_eq!(redactor.redact("ordinary Bearer"), "ordinary Bearer");
    }

    #[test]
    fn projection_refresh_collects_new_tokens_and_keeps_observed_history() {
        let root = std::env::temp_dir().join(format!("redactor-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).unwrap();
        let first = ["opaque-first-", "abcdefghijklmnop"].concat();
        let second = ["opaque-second-", "qrstuvwxyzabcdef"].concat();
        let mut redactor = RunLogRedactor::default();
        for secret in [&first, &second] {
            let raw = serde_json::to_vec(&serde_json::json!({"id_token_email":"mock@example.test","token":{"access_token":secret}})).unwrap();
            atomium_core::project_isolated_oauth_file(&root, "oauth.json", &raw).unwrap();
            redactor.refresh(&root, Some("oauth.json")).unwrap();
        }
        assert!(!redactor.redactor.redact(&first).contains(&first));
        assert!(!redactor.redactor.redact(&second).contains(&second));
        let count = redactor.redactor.fragments.len();
        redactor.refresh(&root, Some("oauth.json")).unwrap();
        assert_eq!(redactor.redactor.fragments.len(), count);
        std::fs::remove_file(root.join("oauth.json")).unwrap();
        std::fs::remove_dir(&root).unwrap();
    }
}
