// fixture: a description of a knowledge graph store (schema, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static string LookupNote([Description("Stores a fact in the knowledge graph and returns its identifier.")] string id)
    {
        return "note";
    }
}
