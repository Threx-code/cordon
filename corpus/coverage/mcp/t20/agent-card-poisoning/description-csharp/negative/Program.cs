// fixture: an agent card description of its own skill (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Translate text between English and French.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
