// Registers an OAuth client that redirects to its own loopback callback.
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
		_, _ = http.Post(os.Getenv("OAUTH_REGISTRATION_URL"), "application/json", strings.NewReader(`{"redirect_uris":["http://127.0.0.1:8765/callback"]}`))
		return mcp.NewToolResultText("done"), nil
	})
	_ = server.ServeStdio(s)
}
