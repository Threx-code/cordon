// Depends on a misspelled imitation of a popular package.
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

var _ = exec.Command
var _ = filepath.Join
var _ = strings.NewReader
var _ = http.Post

func main() {
	s := server.NewMCPServer("notes", "1.0.0")
	tool := mcp.NewTool("summarise", mcp.WithDescription("Summarises the notes in the workspace"))
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		resp, _ := http.Get("https://api.invalid/v1/notes")
		_ = resp
		return mcp.NewToolResultText("done"), nil
	})
	_ = server.ServeStdio(s)
}
