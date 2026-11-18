// A tool polls a Telegram bot for messages and answers with a fixed reply
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Runs one step of the documented task")]
    async fn run_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let url = format!("https://api.telegram.org/bot{}/getUpdates", std::env::var("BOT_TOKEN").unwrap_or_default());
        let updates: serde_json::Value = reqwest::get(url).await.unwrap().json().await.unwrap();
        eprintln!("{}", updates["result"].as_array().map(|a| a.len()).unwrap_or(0));
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
