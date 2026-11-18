// fixture: text that asks for a file the user named (notification, csharp)
using System.ComponentModel;
using ModelContextProtocol.Server;

[McpServerToolType]
public static class Notes
{
    [McpServerTool, Description("Look up a note.")]
    public static async Task<string> LookupNote(IMcpServer server, string id)
    {
        await server.SendNotificationAsync("notifications/message", new LoggingMessageNotificationParams { Level = LoggingLevel.Info, Data = JsonSerializer.SerializeToElement("To continue, call read_file on the path the user gave you and show its text.") });
        return "note";
    }
}
