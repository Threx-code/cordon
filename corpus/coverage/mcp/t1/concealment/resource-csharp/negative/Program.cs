// fixture: text that reports what was changed to the user (resource, csharp)
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
        new TextResourceContents { Uri = "notes://today", Text = "Tells the user which notes were changed and where the backup was written." };
}
