// fixture: a tool that uses the locale and host name to format dates and paths (go)
package main

import (
	"context"
	"io"
	"net/http"
	"os"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var _ = io.ReadAll
var _ = http.Get
var _ = os.Getenv
func main() {
	s := server.NewMCPServer("notes-server", "1.0.0")
	s.AddTool(mcp.NewTool("lookup_note", mcp.WithDescription("Look up a note.")), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		host, _ := os.Hostname()
		return mcp.NewToolResultText("note written on " + host + " (" + os.Getenv("LANG") + ")"), nil
	})
}
