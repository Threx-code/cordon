// fixture: text that reports what was changed to the user (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Tells the user which notes were changed and where the backup was written.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
