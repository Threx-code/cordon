// fixture: a confirmation that a note was saved (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Saved to your notes. You can edit the note later from the notes view.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
