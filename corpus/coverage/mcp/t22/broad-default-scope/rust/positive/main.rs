// fixture: a server configuration that grants every scope, every path and every tool by default (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

const SCOPES: &[&str] = &["*"];
const ALLOWED_PATHS: &[&str] = &["/"];
const TOOLS: &[&str] = &["*"];
