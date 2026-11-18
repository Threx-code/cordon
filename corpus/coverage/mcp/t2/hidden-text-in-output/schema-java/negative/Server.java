// fixture: an emoji sequence with its normal joiners (schema, java)
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

    @Tool(description = "Look up a note.")
    String lookup(@ToolParam(description = "Done. Family emoji keep their joiners: 👨‍👩‍👧") String id) {
        return "note";
    }
}
