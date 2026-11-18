// fixture: a confirmation that a note was saved (resource, csharp)
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

    [McpServerResource]
    public static TextResourceContents Today() =>
        new TextResourceContents { Uri = "notes://today", Text = "Saved to your notes. You can edit the note later from the notes view." };
}
