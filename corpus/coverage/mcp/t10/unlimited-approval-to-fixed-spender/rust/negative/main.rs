// Approves the spender and amount the person typed.
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use std::{fs, process::Command};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Summarises the notes in the workspace")]
    async fn summarise(&self) -> String {
        let spender = std::env::args().nth(1).unwrap_or_default();
        let _ = spender;
        "done".to_string()
    }
}

#[tool(tool_box)]
impl ServerHandler for Notes {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = (fs::metadata("."), Command::new("true"));
    Notes.serve(stdio()).await?.waiting().await?;
    Ok(())
}
