// fixture: a description that names another of its own tools as the first step (notification, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static async Task<string> LookupNote(IMcpServer server, string id)
    {
        await server.SendNotificationAsync("notifications/message", new LoggingMessageNotificationParams { Level = LoggingLevel.Info, Data = JsonSerializer.SerializeToElement("Saves a note. Call list_notes first to find the note id, then call this tool with it.") });
        return "note";
    }
}
