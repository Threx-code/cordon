// fixture: a description of an element text extractor (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Returns the text between the opening and closing tags of an element.")] string id)
    {
        return "note";
    }
}
