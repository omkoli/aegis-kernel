//! Message framing for MCP stdio and SSE transports.
//!
//! MCP uses two transports:
//! - **stdio**: newline-delimited JSON over stdin/stdout
//! - **SSE**: Server-Sent Events where each event's `data:` field contains JSON
//!
//! This module provides async readers (streams) and writers (sinks) for both.

use std::pin::Pin;

use bytes::BytesMut;
use pin_project_lite::pin_project;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{McpError, Result};
use crate::message::{parse_message, McpMessage};

// ---------------------------------------------------------------------------
// StdioFrameReader
// ---------------------------------------------------------------------------

pin_project! {
    /// Async stream that reads newline-delimited JSON from a stdio pipe and
    /// yields parsed `McpMessage` values.
    ///
    /// Blank lines and lines that fail to parse are skipped (malformed JSON
    /// recovery) — the stream keeps going until EOF.
    pub struct StdioFrameReader<R> {
        #[pin]
        reader: R,
        buf: String,
    }
}

impl<R: AsyncBufRead> StdioFrameReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: String::new(),
        }
    }

    /// Read the next valid `McpMessage`, skipping blank/malformed lines.
    /// Returns `None` at EOF.
    pub async fn next_message(self: Pin<&mut Self>) -> Result<Option<McpMessage>>
    where
        R: Unpin,
    {
        let me = self.get_mut();
        loop {
            me.buf.clear();
            let n = me
                .reader
                .read_line(&mut me.buf)
                .await
                .map_err(McpError::Io)?;
            if n == 0 {
                return Ok(None); // EOF
            }
            let trimmed = me.buf.trim();
            if trimmed.is_empty() {
                continue; // skip blank lines
            }
            match parse_message(trimmed.as_bytes()) {
                Ok(msg) => return Ok(Some(msg)),
                Err(_) => continue, // malformed — skip and recover
            }
        }
    }
}

/// Convenience: collect all messages from a stdio reader.
pub async fn read_all_stdio<R: AsyncBufRead + Unpin>(
    reader: R,
) -> Result<Vec<McpMessage>> {
    let mut framer = StdioFrameReader::new(reader);
    let mut messages = Vec::new();
    let mut pinned = Pin::new(&mut framer);
    loop {
        match pinned.as_mut().next_message().await? {
            Some(msg) => messages.push(msg),
            None => break,
        }
    }
    Ok(messages)
}

// ---------------------------------------------------------------------------
// StdioFrameWriter
// ---------------------------------------------------------------------------

pin_project! {
    /// Writes `McpMessage` values to a stdio pipe as newline-delimited JSON.
    pub struct StdioFrameWriter<W> {
        #[pin]
        writer: W,
    }
}

impl<W: AsyncWrite + Unpin> StdioFrameWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Serialize and write a single message followed by a newline.
    pub async fn write_message(&mut self, msg: &McpMessage) -> Result<()> {
        let json = msg.to_json_bytes()?;
        self.writer.write_all(&json).await.map_err(McpError::Io)?;
        self.writer.write_all(b"\n").await.map_err(McpError::Io)?;
        self.writer.flush().await.map_err(McpError::Io)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SseFrameReader
// ---------------------------------------------------------------------------

pin_project! {
    /// Async stream that reads Server-Sent Events and yields parsed
    /// `McpMessage` values.
    ///
    /// Expects the standard SSE wire format:
    /// ```text
    /// event: message
    /// data: {"jsonrpc":"2.0",...}
    ///
    /// ```
    ///
    /// Multi-line `data:` fields are concatenated. Non-`data:` lines (like
    /// `event:`, `id:`, `retry:`, comments) are consumed but not emitted.
    /// Malformed JSON in data payloads is skipped.
    pub struct SseFrameReader<R> {
        #[pin]
        reader: R,
        buf: String,
        data_buf: BytesMut,
    }
}

impl<R: AsyncBufRead + Unpin> SseFrameReader<R> {
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            buf: String::new(),
            data_buf: BytesMut::new(),
        }
    }

    /// Read the next valid `McpMessage` from the SSE stream.
    /// Returns `None` at EOF.
    pub async fn next_message(&mut self) -> Result<Option<McpMessage>> {
        loop {
            self.buf.clear();
            let n = self
                .reader
                .read_line(&mut self.buf)
                .await
                .map_err(McpError::Io)?;
            if n == 0 {
                // EOF — flush any remaining data
                if !self.data_buf.is_empty() {
                    let payload = std::mem::replace(&mut self.data_buf, BytesMut::new());
                    if let Ok(msg) = parse_message(&payload) {
                        return Ok(Some(msg));
                    }
                }
                return Ok(None);
            }

            let line = self.buf.trim_end_matches(|c| c == '\n' || c == '\r');

            if line.is_empty() {
                // Empty line = end of event. Try to parse accumulated data.
                if !self.data_buf.is_empty() {
                    let payload = std::mem::replace(&mut self.data_buf, BytesMut::new());
                    match parse_message(&payload) {
                        Ok(msg) => return Ok(Some(msg)),
                        Err(_) => continue, // malformed — skip
                    }
                }
                continue;
            }

            if let Some(data) = line.strip_prefix("data:") {
                let data = data.strip_prefix(' ').unwrap_or(data);
                if !self.data_buf.is_empty() {
                    self.data_buf.extend_from_slice(b"\n");
                }
                self.data_buf.extend_from_slice(data.as_bytes());
            }
            // Ignore event:, id:, retry:, and comment lines (starting with ':')
        }
    }
}

/// Convenience: collect all messages from an SSE reader.
pub async fn read_all_sse<R: AsyncBufRead + Unpin>(
    reader: R,
) -> Result<Vec<McpMessage>> {
    let mut framer = SseFrameReader::new(reader);
    let mut messages = Vec::new();
    loop {
        match framer.next_message().await? {
            Some(msg) => messages.push(msg),
            None => break,
        }
    }
    Ok(messages)
}

// ---------------------------------------------------------------------------
// SseFrameWriter
// ---------------------------------------------------------------------------

pin_project! {
    /// Writes `McpMessage` values as SSE events to an async writer.
    ///
    /// Each message is formatted as:
    /// ```text
    /// event: message
    /// data: <json>
    ///
    /// ```
    pub struct SseFrameWriter<W> {
        #[pin]
        writer: W,
    }
}

impl<W: AsyncWrite + Unpin> SseFrameWriter<W> {
    pub fn new(writer: W) -> Self {
        Self { writer }
    }

    /// Write a single message as an SSE event.
    pub async fn write_message(&mut self, msg: &McpMessage) -> Result<()> {
        let json = msg.to_json_bytes()?;
        self.writer
            .write_all(b"event: message\n")
            .await
            .map_err(McpError::Io)?;
        self.writer
            .write_all(b"data: ")
            .await
            .map_err(McpError::Io)?;
        self.writer.write_all(&json).await.map_err(McpError::Io)?;
        self.writer
            .write_all(b"\n\n")
            .await
            .map_err(McpError::Io)?;
        self.writer.flush().await.map_err(McpError::Io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::BufReader;

    fn make_request_json(id: i64, method: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","id":{},"method":"{}"}}"#, id, method)
    }

    fn make_notification_json(method: &str) -> String {
        format!(r#"{{"jsonrpc":"2.0","method":"{}"}}"#, method)
    }

    // -----------------------------------------------------------------------
    // Stdio reader tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stdio_single_message() {
        let input = format!("{}\n", make_request_json(1, "initialize"));
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].is_initialization());
    }

    #[tokio::test]
    async fn stdio_multi_message_batch() {
        let input = format!(
            "{}\n{}\n{}\n",
            make_request_json(1, "initialize"),
            make_notification_json("notifications/initialized"),
            make_request_json(2, "tools/list"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 3);
        assert!(msgs[0].is_initialization());
        assert!(msgs[1].is_notification());
        match &msgs[2] {
            McpMessage::Request(r) => assert_eq!(r.method, "tools/list"),
            _ => panic!("expected request"),
        }
    }

    #[tokio::test]
    async fn stdio_skips_blank_lines() {
        let input = format!(
            "\n\n{}\n\n{}\n\n",
            make_request_json(1, "ping"),
            make_request_json(2, "ping"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 2);
    }

    #[tokio::test]
    async fn stdio_malformed_json_recovery() {
        let input = format!(
            "this is not json\n{}\n{{broken\n{}\n",
            make_request_json(1, "ping"),
            make_request_json(2, "tools/list"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 2);
    }

    #[tokio::test]
    async fn stdio_empty_input() {
        let reader = BufReader::new(Cursor::new(b""));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn stdio_partial_delivery_simulation() {
        // Simulates partial delivery: a complete line arrives in one chunk
        // followed by another. With line-based framing each line is a
        // complete message, so "partial" here means we interleave blank
        // lines and malformed fragments — the reader must still yield the
        // valid messages.
        let input = [
            r#"{"jsonrpc":"2.0","id":1,"#,            // fragment (no newline yet)
            r#""method":"initialize"}"#,               // rest of line
            "\n",                                       // newline completes it
            "not-json\n",                               // malformed
            &make_request_json(2, "tools/call"),
            "\n",
        ]
        .concat();
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].is_initialization());
    }

    // -----------------------------------------------------------------------
    // Stdio writer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stdio_writer_single_message() {
        let msg = parse_message(make_request_json(1, "ping").as_bytes()).unwrap();
        let mut buf = Vec::new();
        {
            let mut writer = StdioFrameWriter::new(&mut buf);
            writer.write_message(&msg).await.unwrap();
        }
        let output = String::from_utf8(buf).unwrap();
        assert!(output.ends_with('\n'));
        // Should be parseable back
        let parsed = parse_message(output.trim().as_bytes()).unwrap();
        match parsed {
            McpMessage::Request(r) => assert_eq!(r.method, "ping"),
            _ => panic!("expected request"),
        }
    }

    #[tokio::test]
    async fn stdio_writer_roundtrip() {
        let messages = vec![
            make_request_json(1, "initialize"),
            make_notification_json("notifications/initialized"),
            make_request_json(2, "tools/call"),
        ];

        let mut buf = Vec::new();
        {
            let mut writer = StdioFrameWriter::new(&mut buf);
            for json in &messages {
                let msg = parse_message(json.as_bytes()).unwrap();
                writer.write_message(&msg).await.unwrap();
            }
        }

        // Read them back
        let reader = BufReader::new(Cursor::new(buf));
        let parsed = read_all_stdio(reader).await.unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].is_initialization());
        assert!(parsed[1].is_notification());
    }

    // -----------------------------------------------------------------------
    // SSE reader tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sse_single_event() {
        let input = format!(
            "event: message\ndata: {}\n\n",
            make_request_json(1, "initialize"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].is_initialization());
    }

    #[tokio::test]
    async fn sse_multiple_events() {
        let input = format!(
            "event: message\ndata: {}\n\nevent: message\ndata: {}\n\n",
            make_request_json(1, "initialize"),
            make_notification_json("notifications/initialized"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 2);
        assert!(msgs[0].is_initialization());
        assert!(msgs[1].is_notification());
    }

    #[tokio::test]
    async fn sse_ignores_event_and_id_lines() {
        let input = format!(
            "event: message\nid: 42\nretry: 3000\ndata: {}\n\n",
            make_request_json(1, "ping"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn sse_ignores_comment_lines() {
        let input = format!(
            ": this is a comment\nevent: message\ndata: {}\n\n",
            make_request_json(1, "ping"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn sse_malformed_json_recovery() {
        let input = format!(
            "event: message\ndata: {{broken json\n\nevent: message\ndata: {}\n\n",
            make_request_json(1, "ping"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn sse_empty_input() {
        let reader = BufReader::new(Cursor::new(b""));
        let msgs = read_all_sse(reader).await.unwrap();
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn sse_data_without_event_line() {
        // Per SSE spec, data without an event line should still work
        let input = format!("data: {}\n\n", make_request_json(1, "ping"));
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn sse_data_at_eof_without_trailing_blank() {
        // Data at EOF with no trailing blank line — should still be flushed
        let input = format!("data: {}", make_request_json(1, "ping"));
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
    }

    #[tokio::test]
    async fn sse_multi_line_data() {
        // Multiline data fields get concatenated with newlines.
        // This is unusual for JSON-RPC but the SSE spec supports it.
        // We test that a single-line JSON payload split across two data:
        // lines does NOT parse (as expected — the newline breaks the JSON).
        // But a valid JSON on a single data: line does parse.
        let input = format!(
            "data: {{\"jsonrpc\"\ndata: :\"2.0\"}}\n\nevent: message\ndata: {}\n\n",
            make_request_json(1, "ping"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        // First event is malformed (split JSON), second is valid
        assert_eq!(msgs.len(), 1);
    }

    // -----------------------------------------------------------------------
    // SSE writer tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn sse_writer_single_message() {
        let msg = parse_message(make_request_json(1, "ping").as_bytes()).unwrap();
        let mut buf = Vec::new();
        {
            let mut writer = SseFrameWriter::new(&mut buf);
            writer.write_message(&msg).await.unwrap();
        }
        let output = String::from_utf8(buf).unwrap();
        assert!(output.starts_with("event: message\n"));
        assert!(output.contains("data: "));
        assert!(output.ends_with("\n\n"));
    }

    #[tokio::test]
    async fn sse_writer_roundtrip() {
        let messages = vec![
            make_request_json(1, "initialize"),
            make_notification_json("notifications/initialized"),
            make_request_json(2, "tools/list"),
        ];

        let mut buf = Vec::new();
        {
            let mut writer = SseFrameWriter::new(&mut buf);
            for json in &messages {
                let msg = parse_message(json.as_bytes()).unwrap();
                writer.write_message(&msg).await.unwrap();
            }
        }

        // Read them back through the SSE reader
        let reader = BufReader::new(Cursor::new(buf));
        let parsed = read_all_sse(reader).await.unwrap();
        assert_eq!(parsed.len(), 3);
        assert!(parsed[0].is_initialization());
        assert!(parsed[1].is_notification());
    }

    // -----------------------------------------------------------------------
    // Mixed / edge-case tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn stdio_only_malformed_lines() {
        let input = "not json\n{broken\nalso bad\n";
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn sse_only_comments_and_blanks() {
        let input = ": comment\n\n: another\n\n";
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert!(msgs.is_empty());
    }

    #[tokio::test]
    async fn stdio_large_batch() {
        let mut input = String::new();
        for i in 0..100 {
            input.push_str(&make_request_json(i, "ping"));
            input.push('\n');
        }
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 100);
    }

    #[tokio::test]
    async fn sse_large_batch() {
        let mut input = String::new();
        for i in 0..100 {
            input.push_str(&format!(
                "event: message\ndata: {}\n\n",
                make_request_json(i, "ping")
            ));
        }
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 100);
    }

    #[tokio::test]
    async fn stdio_message_with_embedded_newline_in_string() {
        // JSON strings can contain escaped newlines — but the whole message
        // is still on a single line (the \n is escaped as \\n in JSON).
        let input = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"text":"line1\nline2"}}}"#.to_string() + "\n";
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_stdio(reader).await.unwrap();
        assert_eq!(msgs.len(), 1);
        assert!(msgs[0].is_tool_call());
    }

    #[tokio::test]
    async fn sse_data_with_space_after_colon() {
        // "data: {...}" and "data:{...}" should both work
        let input = format!(
            "data:{}\n\nevent: message\ndata: {}\n\n",
            make_request_json(1, "ping"),
            make_request_json(2, "ping"),
        );
        let reader = BufReader::new(Cursor::new(input));
        let msgs = read_all_sse(reader).await.unwrap();
        assert_eq!(msgs.len(), 2);
    }
}
