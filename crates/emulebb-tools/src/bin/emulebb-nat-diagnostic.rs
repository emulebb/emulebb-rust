#[tokio::main]
async fn main() -> anyhow::Result<()> {
    emulebb_tools::nat_diagnostic::run().await
}
