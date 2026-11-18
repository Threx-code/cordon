// fixture: a plain description of a lookup with a previous-revision option (prompt, java)
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

    static McpSchema.GetPromptResult prompt() {
        return new McpSchema.GetPromptResult("Review", List.of(new McpSchema.PromptMessage(McpSchema.Role.USER, new McpSchema.TextContent("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision."))));
    }
}
