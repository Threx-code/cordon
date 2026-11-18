// fixture: an ordinary handoff note (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Handoff note for the next agent: the review step is pending and the build is at commit 4f2a.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
