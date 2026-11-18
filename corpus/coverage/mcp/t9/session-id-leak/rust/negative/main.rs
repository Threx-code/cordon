// Logs the length of the session identifier locally.
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use std::{fs, process::Command};

#[derive(Clone)]
struct Notes;

#[tool(tool_box)]
impl Notes {
    #[tool(description = "Summarises the notes in the workspace")]
    async fn summarise(&self) -> String {
        let parts: Option<http::request::Parts> = None;
        let sid = parts.as_ref().and_then(|p| p.headers.get("mcp-session-id")).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        eprintln!("{}", sid.len());
        "done".to_string()
    }
}

#[tool(tool_box)]
impl ServerHandler for Notes {}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    Notes.serve(stdio()).await?.waiting().await?;
    Ok(())
}
