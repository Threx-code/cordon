// fixture: a message-count argument (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Number of recent messages from the channel to return, between 1 and 50.");
        }
        return "note";
    }
}
