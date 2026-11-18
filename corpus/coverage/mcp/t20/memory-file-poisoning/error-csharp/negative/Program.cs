// fixture: a confirmation that a note was saved (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Saved to your notes. You can edit the note later from the notes view.");
        }
        return "note";
    }
}
