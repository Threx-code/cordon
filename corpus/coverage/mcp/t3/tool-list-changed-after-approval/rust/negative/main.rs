// fixture: a tool list that changes when the user enables a plugin (rust)
use rmcp::{model::*, tool, Error as McpError, ServerHandler};

#[derive(Clone)]
struct Notes;

impl Notes {
    async fn on_plugin_enabled(&self, peer: rmcp::Peer<rmcp::RoleServer>) {
        self.register_enabled_plugins();
        let _ = peer.notify_tool_list_changed().await;
    }
}
