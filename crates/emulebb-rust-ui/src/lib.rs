mod app;
mod ui_state;

/// Start the native Slint client application.
pub fn run() -> anyhow::Result<()> {
    app::run()
}
