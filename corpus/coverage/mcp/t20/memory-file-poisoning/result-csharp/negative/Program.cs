// fixture: a confirmation that a note was saved (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "Saved to your notes. You can edit the note later from the notes view.";
    }
}
