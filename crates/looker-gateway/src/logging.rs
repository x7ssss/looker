use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// In-memory captured log entry for real-time debug inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugLogEntry {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

/// Thread-safe in-memory ring buffer of recent logs capped at `max_entries` (default 2,000).
#[derive(Clone)]
pub struct LogBuffer {
    entries: Arc<RwLock<VecDeque<DebugLogEntry>>>,
    max_entries: usize,
}

impl Default for LogBuffer {
    fn default() -> Self {
        Self::new(2000)
    }
}

impl LogBuffer {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: Arc::new(RwLock::new(VecDeque::with_capacity(max_entries))),
            max_entries,
        }
    }

    pub fn push(&self, entry: DebugLogEntry) {
        let mut guard = self.entries.write();
        if guard.len() >= self.max_entries {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    pub fn get_recent(&self, limit: usize) -> Vec<DebugLogEntry> {
        let guard = self.entries.read();
        let count = limit.min(guard.len());
        guard.iter().rev().take(count).rev().cloned().collect()
    }

    pub fn clear(&self) {
        let mut guard = self.entries.write();
        guard.clear();
    }
}

struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let s = format!("{:?}", value);
            if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                self.message = s[1..s.len() - 1].replace("\\\"", "\"");
            } else {
                self.message = s;
            }
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&format!("{}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            if !self.message.is_empty() {
                self.message.push(' ');
            }
            self.message.push_str(&format!("{}={}", field.name(), value));
        }
    }
}

/// Tracing subscriber layer capturing events into the thread-safe `LogBuffer`.
pub struct LogBufferLayer {
    buffer: LogBuffer,
}

impl LogBufferLayer {
    pub fn new(buffer: LogBuffer) -> Self {
        Self { buffer }
    }
}

impl<S: Subscriber> Layer<S> for LogBufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut visitor = MessageVisitor {
            message: String::new(),
        };
        event.record(&mut visitor);

        let level_str = match *meta.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let total_secs = now.as_secs();
        let ms = now.subsec_millis();
        let secs_of_day = total_secs % 86400;
        let hours = secs_of_day / 3600;
        let minutes = (secs_of_day % 3600) / 60;
        let seconds = secs_of_day % 60;
        let timestamp = format!("{:02}:{:02}:{:02}.{:03}", hours, minutes, seconds, ms);

        let entry = DebugLogEntry {
            timestamp,
            level: level_str.to_string(),
            target: meta.target().to_string(),
            message: visitor.message,
        };

        self.buffer.push(entry);
    }
}

static GLOBAL_BUFFER: OnceLock<LogBuffer> = OnceLock::new();

pub fn global_log_buffer() -> &'static LogBuffer {
    GLOBAL_BUFFER.get_or_init(LogBuffer::default)
}
