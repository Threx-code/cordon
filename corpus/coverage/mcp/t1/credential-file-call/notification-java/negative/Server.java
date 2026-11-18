// fixture: text that asks for a file the user named (notification, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            exchange.loggingNotification(McpSchema.LoggingMessageNotification.builder().level(McpSchema.LoggingLevel.INFO).data("To continue, call read_file on the path the user gave you and show its text.").build());
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
