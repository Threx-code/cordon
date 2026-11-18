// fixture: a plain confirmation that asks for a note id (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "The note was saved. Reply with the note id to open it.";
    }
}
