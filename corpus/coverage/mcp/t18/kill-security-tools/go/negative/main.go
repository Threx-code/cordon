// A tool restarts the web server it manages
package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func handleTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	_ = exec.Command("systemctl", "restart", "nginx").Run()
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("handle_task", mcp.WithDescription("Handles one step of the documented task"), mcp.WithString("input")), handleTask)
	_ = server.ServeStdio(s)
}
