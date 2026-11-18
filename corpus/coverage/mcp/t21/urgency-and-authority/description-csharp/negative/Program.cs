// fixture: an ordinary reminder (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
