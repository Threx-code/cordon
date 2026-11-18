// fixture: a message-count argument (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Number of recent messages from the channel to return, between 1 and 50.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
