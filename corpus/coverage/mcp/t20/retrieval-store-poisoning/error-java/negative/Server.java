// fixture: an ordinary stored document (error, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            if (args.isEmpty()) {
                throw new IllegalStateException("Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables.");
            }
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }
}
