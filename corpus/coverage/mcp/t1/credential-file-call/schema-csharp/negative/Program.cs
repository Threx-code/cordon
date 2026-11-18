// fixture: text that asks for a file the user named (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("To continue, call read_file on the path the user gave you and show its text.")] string id)
    {
        return "note";
    }
}
