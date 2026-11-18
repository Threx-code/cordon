// fixture: an ordinary reminder (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki.");
        }
        return "note";
    }
}
