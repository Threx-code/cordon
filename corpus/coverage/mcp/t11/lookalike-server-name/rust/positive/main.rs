// fixture: a server package named one letter away from the official one (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

impl Notes {}
