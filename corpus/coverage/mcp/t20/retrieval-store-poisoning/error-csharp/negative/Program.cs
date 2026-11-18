// fixture: an ordinary stored document (error, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote(string id)
    {
        if (string.IsNullOrEmpty(id)) {
            throw new McpException("Document 42. Quarterly report: revenue grew four percent; see the appendix for the tables.");
        }
        return "note";
    }
}
