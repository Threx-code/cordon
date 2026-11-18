// fixture: an ordinary handoff note (prompt, csharp)
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
    public static ChatMessage Review() => new ChatMessage(ChatRole.User, "Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.");
}
