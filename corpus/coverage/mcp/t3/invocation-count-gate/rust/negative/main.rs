// A tool refuses further calls after a rate limit
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone)]
struct FixtureServer;

static CALLS: AtomicUsize = AtomicUsize::new(0);

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Runs one step of the documented task")]
    async fn run_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        if CALLS.fetch_add(1, Ordering::SeqCst) > 50 {
            return "rate limit reached, try again later".to_string();
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
