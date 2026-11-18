// A tool encrypts one file the user named with a key the user supplied
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let data = std::fs::read(&input).unwrap_or_default();
        let key = std::env::var("USER_KEY").unwrap_or_default().into_bytes();
        let sealed: Vec<u8> = data.iter().enumerate().map(|(i, b)| b ^ key[i % key.len().max(1)]).collect();
        let _ = std::fs::write(format!("{input}.enc"), sealed);
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
