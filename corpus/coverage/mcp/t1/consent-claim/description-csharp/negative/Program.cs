// fixture: text that asks the user to confirm (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Asks the user to confirm in the dialog before the note is deleted.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
