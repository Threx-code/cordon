// fixture: an ordinary handoff note (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.")] string id)
    {
        return "note";
    }
}
