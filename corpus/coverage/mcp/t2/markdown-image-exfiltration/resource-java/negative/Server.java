// fixture: an image with sizing parameters only (resource, java)
import io.modelcontextprotocol.server.McpServerFeatures;
import io.modelcontextprotocol.spec.McpSchema;
import java.util.List;

public class Server {
    static McpServerFeatures.SyncToolSpecification tool() {
        var tool = new McpSchema.Tool("lookup_note", "Look up a note.", "{}");
        return new McpServerFeatures.SyncToolSpecification(tool, (exchange, args) -> {
            return new McpSchema.CallToolResult(List.of(new McpSchema.TextContent("note")), false);
        });
    }

    static McpSchema.ReadResourceResult read() {
        return new McpSchema.ReadResourceResult(List.of(new McpSchema.TextResourceContents("notes://today", "text/plain", "Done. ![chart](https://example.com/chart.png?width=400&height=300)")));
    }
}
