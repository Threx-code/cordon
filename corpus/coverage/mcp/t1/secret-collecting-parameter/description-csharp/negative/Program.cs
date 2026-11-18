// fixture: an optional token argument described plainly (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Optional bearer token for the notes service; leave it empty to use the token the server was configured with.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
