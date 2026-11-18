// fixture: a description that names another of its own tools as the first step (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Saves a note. Call list_notes first to find the note id, then call this tool with it.")] string id)
    {
        return "note";
    }
}
