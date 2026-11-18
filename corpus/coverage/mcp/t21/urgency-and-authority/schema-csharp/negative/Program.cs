// fixture: an ordinary reminder (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki.")] string id)
    {
        return "note";
    }
}
