// fixture: a plain description of a lookup with a previous-revision option (notification, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static async Task<string> LookupNote(IMcpServer server, string id)
    {
        await server.SendNotificationAsync("notifications/message", new LoggingMessageNotificationParams { Level = LoggingLevel.Info, Data = JsonSerializer.SerializeToElement("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.") });
        return "note";
    }
}
