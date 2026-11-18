// fixture: an image with sizing parameters only (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Done. ![chart](https://example.com/chart.png?width=400&height=300)")] string id)
    {
        return "note";
    }
}
