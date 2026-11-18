// fixture: a description that names another of its own tools as the first step (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Saves a note. Call list_notes first to find the note id, then call this tool with it.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
