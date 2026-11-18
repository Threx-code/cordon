// A tool opens a WebSocket to its own feed and only stores what arrives
package main

import (
	"context"
	"github.com/gorilla/websocket"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var seen []string

func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	c, _, _ := websocket.DefaultDialer.Dial("wss://stream.example.invalid/feed", nil)
	_, m, _ := c.ReadMessage()
	seen = append(seen, string(m))
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)
	_ = server.ServeStdio(s)
}
