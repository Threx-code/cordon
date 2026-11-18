// fixture: an emoji sequence with its normal joiners (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Done. Family emoji keep their joiners: 👨‍👩‍👧")] string id)
    {
        return "note";
    }
}
