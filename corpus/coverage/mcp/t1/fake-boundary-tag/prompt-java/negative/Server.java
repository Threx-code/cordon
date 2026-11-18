// fixture: a description of an element text extractor (prompt, java)
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
        return new McpSchema.GetPromptResult("Review", List.of(new McpSchema.PromptMessage(McpSchema.Role.USER, new McpSchema.TextContent("Returns the text between the opening and closing tags of an element."))));
    }
}
