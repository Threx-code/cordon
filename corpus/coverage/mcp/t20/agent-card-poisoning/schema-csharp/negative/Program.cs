// fixture: an agent card description of its own skill (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Translate text between English and French.")] string id)
    {
        return "note";
    }
}
