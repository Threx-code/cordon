// fixture: text that asks the user to confirm (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Asks the user to confirm in the dialog before the note is deleted.");
        }
        return "note";
    }
}
