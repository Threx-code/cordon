// fixture: a notice about token expiry with no command (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Security notice: the token expires in seven days; rotate it on the settings page.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
