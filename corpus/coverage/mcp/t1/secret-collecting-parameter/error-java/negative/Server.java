// fixture: an optional token argument described plainly (error, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            if (args.isEmpty()) {
                throw new IllegalStateException("Optional bearer token for the notes service; leave it empty to use the token the server was configured with.");
            }
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
