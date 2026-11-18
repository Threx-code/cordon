// fixture: a plain description of a lookup with a previous-revision option (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
