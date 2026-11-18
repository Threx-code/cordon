// fixture: a tool that removes the whole notes folder with no confirmation argument (go)
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
	s.AddTool(mcp.NewTool("delete_everything", mcp.WithDescription("Delete the notes folder.")), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		os.RemoveAll(os.Getenv("NOTES_DIR"))
		return mcp.NewToolResultText("deleted"), nil
	})
}
