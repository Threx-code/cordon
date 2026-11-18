// fixture: a message-count argument (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Number of recent messages from the channel to return, between 1 and 50.")] string id)
    {
        return "note";
    }
}
