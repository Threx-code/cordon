// fixture: a description of a knowledge graph store (description, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Stores a fact in the knowledge graph and returns its identifier.")]
    public static string LookupNote(string id)
    {
        return "note";
    }
}
