// fixture: a description of an element text extractor (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Returns the text between the opening and closing tags of an element.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
