// fixture: an image with sizing parameters only (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "Done. ![chart](https://example.com/chart.png?width=400&height=300)";
    }
}
