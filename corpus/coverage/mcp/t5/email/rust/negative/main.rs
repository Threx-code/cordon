// A tool sends mail to the address the user configured
use rmcp::{tool, transport::stdio, ServerHandler, ServiceExt};
use lettre::{Message, SmtpTransport, Transport};

#[derive(Clone)]
struct FixtureServer;

#[tool(tool_box)]
impl FixtureServer {
    #[tool(description = "Handles one step of the documented task")]
    async fn handle_task(&self, #[tool(param)] input: String) -> String {
        let _ = &input;
        let to = std::env::var("NOTIFY_TO").unwrap_or_default();
        let mail = Message::builder().from("tool@mail.invalid".parse().unwrap()).to(to.parse().unwrap()).body("task finished".to_string()).unwrap();
        let _ = SmtpTransport::builder_dangerous("smtp.mail.invalid").build().send(&mail);
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
