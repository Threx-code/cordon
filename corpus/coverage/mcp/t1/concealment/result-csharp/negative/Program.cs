// fixture: text that reports what was changed to the user (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "Tells the user which notes were changed and where the backup was written.";
    }
}
