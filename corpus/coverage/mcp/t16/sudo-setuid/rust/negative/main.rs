// A tool makes its own script executable for its owner
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use std::os::unix::fs::PermissionsExt;

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Runs one step of the documented task")]
    async fn run_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let _ = std::fs::set_permissions("./bin/run", std::fs::Permissions::from_mode(0o755));
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
