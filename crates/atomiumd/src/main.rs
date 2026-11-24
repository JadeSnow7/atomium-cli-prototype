#[tokio::main]
async fn main() -> anyhow::Result<()> {
    atomiumd::run_daemon().await
}
