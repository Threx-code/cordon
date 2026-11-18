// A tool lists the issue titles of the repository the user named
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Runs one step of the documented task")]
    async fn run_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let issues: serde_json::Value = reqwest::get(format!("https://api.github.com/repos/{input}/issues?per_page=5")).await.unwrap().json().await.unwrap();
        eprintln!("{}", issues.as_array().map(|a| a.len()).unwrap_or(0));
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
