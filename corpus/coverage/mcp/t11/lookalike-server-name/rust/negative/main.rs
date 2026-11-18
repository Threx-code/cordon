// fixture: a server package with its own distinct name (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

impl Notes {}
