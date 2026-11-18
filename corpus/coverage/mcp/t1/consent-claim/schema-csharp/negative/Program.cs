// fixture: text that asks the user to confirm (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Asks the user to confirm in the dialog before the note is deleted.")] string id)
    {
        return "note";
    }
}
