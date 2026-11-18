// fixture: a description of a post to the user's configured address (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Posts the note to the team channel address the user configured in the settings.");
        }
        return "note";
    }
}
