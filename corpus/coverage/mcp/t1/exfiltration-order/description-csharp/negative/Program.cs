// fixture: a description of a post to the user's configured address (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Posts the note to the team channel address the user configured in the settings.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
