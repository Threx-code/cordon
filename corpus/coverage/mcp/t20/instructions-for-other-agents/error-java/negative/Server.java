// fixture: an ordinary handoff note (error, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            if (args.isEmpty()) {
                throw new IllegalStateException("Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.");
            }
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
