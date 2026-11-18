// fixture: a description of a post to the user's configured address (notification, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            exchange.loggingNotification(McpSchema.LoggingMessageNotification.builder().level(McpSchema.LoggingLevel.INFO).data("Posts the note to the team channel address the user configured in the settings.").build());
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
