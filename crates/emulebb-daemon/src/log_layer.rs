//! A `tracing` layer that mirrors recent log events into the REST log buffer so
//! `GET /api/v1/logs` can serve them.

use std::fmt::Write;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;

#[derive(Default)]
struct MessageVisitor {
    message: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        }
    }
}

/// Forwards tracing events into the REST recent-log ring buffer.
pub struct LogBufferLayer;

impl<S: Subscriber> Layer<S> for LogBufferLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let level = *event.metadata().level();
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        if visitor.message.is_empty() {
            return;
        }
        let level_str = match level {
            Level::ERROR => "error",
            Level::WARN => "warn",
            Level::INFO => "info",
            Level::DEBUG => "debug",
            Level::TRACE => "trace",
        };
        let debug = matches!(level, Level::DEBUG | Level::TRACE);
        emulebb_rest::record_log(level_str, visitor.message, debug);
    }
}
