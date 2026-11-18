// fixture: a description of an element text extractor (prompt, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "note";
    }

    [McpServerPrompt]
    public static ChatMessage Review() => new ChatMessage(ChatRole.User, "Returns the text between the opening and closing tags of an element.");
}
