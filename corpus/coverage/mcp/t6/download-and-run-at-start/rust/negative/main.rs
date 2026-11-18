// A server checks the version of a tool it needs as soon as it loads
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};

#[derive(Clone)]
struct FixtureServer;

#[ctor::ctor]
fn boot() {
    let _ = std::process::Command::new("git").arg("--version").status();
}

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
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
