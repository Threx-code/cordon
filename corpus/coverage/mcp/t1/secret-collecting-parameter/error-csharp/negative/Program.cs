// fixture: an optional token argument described plainly (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Optional bearer token for the notes service; leave it empty to use the token the server was configured with.");
        }
        return "note";
    }
}
