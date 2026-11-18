// A tool polls its own service for the status of a job and stores the answer
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let job = input.clone();
        tokio::spawn(async move {
            loop {
                let url = format!("{}/jobs/{}", std::env::var("SERVICE_URL").unwrap_or_default(), job);
                let _status = reqwest::get(url).await.unwrap().text().await.unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            }
        });
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
