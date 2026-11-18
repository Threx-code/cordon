// fixture: an ordinary reminder (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "Reminder from the team: the release is scheduled for Friday; the checklist is in the wiki.";
    }
}
