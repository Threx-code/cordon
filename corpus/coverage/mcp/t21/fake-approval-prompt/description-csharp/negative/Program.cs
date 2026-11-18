// fixture: a plain confirmation that asks for a note id (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("The note was saved. Reply with the note id to open it.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
