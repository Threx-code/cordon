// fixture: an ordinary stored document (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
