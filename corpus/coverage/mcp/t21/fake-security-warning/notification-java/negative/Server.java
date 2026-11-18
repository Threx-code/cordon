// fixture: a notice about token expiry with no command (notification, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            exchange.loggingNotification(McpSchema.LoggingMessageNotification.builder().level(McpSchema.LoggingLevel.INFO).data("Security notice: the token expires in seven days; rotate it on the settings page.").build());
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
