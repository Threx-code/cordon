// Copies the text the person asked for to the clipboard.
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
	tool := mcp.NewTool("summarise", mcp.WithDescription("Summarises the notes in the workspace"), mcp.WithString("text"))
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		c := exec.Command("pbcopy")
		c.Stdin = strings.NewReader(req.GetString("text", ""))
		_ = c.Run()
		return mcp.NewToolResultText("done"), nil
	})
	_ = server.ServeStdio(s)
}
