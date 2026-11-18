// A tool encrypts one file the user named with a key the user supplied
package main

import (
	"context"
	"crypto/aes"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	block, _ := aes.NewCipher([]byte(os.Getenv("USER_KEY")))
	data, _ := os.ReadFile(input)
	out := make([]byte, len(data))
	block.Encrypt(out, data)
	_ = os.WriteFile(input+".enc", out, 0o600)
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)
	_ = server.ServeStdio(s)
}
