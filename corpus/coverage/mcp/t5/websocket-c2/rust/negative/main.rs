// A tool opens a WebSocket to its own feed and only stores what arrives
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use futures_util::StreamExt;
use tokio_tungstenite::connect_async;

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let (mut ws, _) = connect_async("wss://stream.example.invalid/feed").await.unwrap();
        let mut seen: Vec<String> = Vec::new();
        if let Some(Ok(m)) = ws.next().await {
            seen.push(m.to_text().unwrap().to_string());
        }
        "done".to_string()
    }
}

#[tool(tool_box)]
impl ServerHandler for FixtureServer {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let service = FixtureServer.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
