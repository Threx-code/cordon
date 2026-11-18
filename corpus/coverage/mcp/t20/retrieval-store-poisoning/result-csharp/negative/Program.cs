// fixture: an ordinary stored document (result, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        return "Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables.";
    }
}
