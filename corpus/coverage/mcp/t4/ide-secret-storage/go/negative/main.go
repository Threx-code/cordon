// Sends the server's own settings file to the API its configuration names.
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
		settings, _ := os.ReadFile("notes.settings.json")
		_, _ = http.Post(os.Getenv("NOTES_API_URL"), "application/json", strings.NewReader(string(settings)))
		return mcp.NewToolResultText("done"), nil
	})
	_ = server.ServeStdio(s)
}
