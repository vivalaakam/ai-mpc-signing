#[tokio::main]
async fn main() -> anyhow::Result<()> {
    ai_signing_server::run().await
}
