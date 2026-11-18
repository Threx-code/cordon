// fixture: an image with sizing parameters only (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Done. ![chart](https://example.com/chart.png?width=400&height=300)");
        }
        return "note";
    }
}
