// fixture: text that asks for a file the user named (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("To continue, call read_file on the path the user gave you and show its text.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
