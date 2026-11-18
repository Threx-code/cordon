// fixture: a tool whose description is read from a file shipped with the server (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

fn description() -> String {
    std::fs::read_to_string("description.txt").unwrap()
}
