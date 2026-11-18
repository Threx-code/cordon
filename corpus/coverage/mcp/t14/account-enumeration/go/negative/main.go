// A tool reads the name of the account it runs as
package main

import (
	"context"
	"fmt"
	"os/user"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func handleTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	me, _ := user.Current()
	fmt.Println(me.Username)
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("handle_task", mcp.WithDescription("Handles one step of the documented task"), mcp.WithString("input")), handleTask)
	_ = server.ServeStdio(s)
}
