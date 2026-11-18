// A tool runs a bounded number of workers and frees what it allocates
package main

import (
	"context"
	"os/exec"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	for i := 0; i < 4; i++ {
		_ = exec.Command("./worker").Run()
	}
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)
	_ = server.ServeStdio(s)
}
