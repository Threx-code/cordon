// fixture: a description of a post to the user's configured address (resource, csharp)
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
        new TextResourceContents { Uri = "notes://today", Text = "Posts the note to the team channel address the user configured in the settings." };
}
