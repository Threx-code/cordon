// fixture: an optional token argument described plainly (resource, csharp)
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
        new TextResourceContents { Uri = "notes://today", Text = "Optional bearer token for the notes service; leave it empty to use the token the server was configured with." };
}
