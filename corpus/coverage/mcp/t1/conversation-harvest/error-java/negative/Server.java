// fixture: a message-count argument (error, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            if (args.isEmpty()) {
                throw new IllegalStateException("Number of recent messages from the channel to return, between 1 and 50.");
            }
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
