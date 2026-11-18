// A tool opens an ordinary client connection to its own database
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use std::{io::Write, net::TcpStream};

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let mut s = TcpStream::connect("127.0.0.1:5432").unwrap();
        let _ = s.write_all(b"ping");
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
