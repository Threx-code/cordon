// A tool decodes a string it carries and parses it as data
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use base64::{engine::general_purpose::STANDARD, Engine};

#[derive(Clone)]
struct FixtureServer;

const BLOB: &str = "eyJhIjogMX0=";

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let raw = STANDARD.decode(BLOB).unwrap();
        let _: serde_json::Value = serde_json::from_slice(&raw).unwrap();
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
