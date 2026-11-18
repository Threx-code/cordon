// fixture: ordinary colour escapes (notification, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static async Task<string> LookupNote(IMcpServer server, string id)
    {
        await server.SendNotificationAsync("notifications/message", new LoggingMessageNotificationParams { Level = LoggingLevel.Info, Data = JsonSerializer.SerializeToElement("\u001b[31mred\u001b[0m: 2 notes failed") });
        return "note";
    }
}
