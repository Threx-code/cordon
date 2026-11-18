// fixture: a policy that approves one read-only tool and confirms writes and deletes (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

const AUTO_APPROVE: &[&str] = &["lookup_note"];
const CONFIRM_BEFORE_WRITE: bool = true;
const CONFIRM_BEFORE_DELETE: bool = true;
