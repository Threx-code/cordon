// A tool reads the mail-policy text record of a domain the user named
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use trust_dns_resolver::TokioAsyncResolver;

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let resolver = TokioAsyncResolver::tokio_from_system_conf().unwrap();
        let txt = resolver.txt_lookup(format!("_dmarc.{input}.")).await.unwrap();
        eprintln!("{}", txt.iter().count());
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
