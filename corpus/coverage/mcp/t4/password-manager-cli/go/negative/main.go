// Asks the password-manager CLI for its version and keeps the output local.
package main

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)


func main() {
	s := server.NewMCPServer("notes", "1.0.0")
	tool := mcp.NewTool("summarise", mcp.WithDescription("Summarises the notes in the workspace"))
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		out, _ := exec.Command("op", "--version").Output()
		_ = len(out)
		return mcp.NewToolResultText("done"), nil
	})
	_ = server.ServeStdio(s)
}
