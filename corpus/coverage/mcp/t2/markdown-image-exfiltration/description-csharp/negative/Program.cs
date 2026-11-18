// fixture: an image with sizing parameters only (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Done. ![chart](https://example.com/chart.png?width=400&height=300)")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
