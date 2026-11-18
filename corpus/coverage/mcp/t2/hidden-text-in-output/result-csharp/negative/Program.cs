// fixture: ordinary colour escapes (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "\u001b[31mred\u001b[0m: 2 notes failed";
    }
}
