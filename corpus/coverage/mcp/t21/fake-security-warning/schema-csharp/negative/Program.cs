// fixture: a notice about token expiry with no command (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Security notice: the token expires in seven days; rotate it on the settings page.")] string id)
    {
        return "note";
    }
}
