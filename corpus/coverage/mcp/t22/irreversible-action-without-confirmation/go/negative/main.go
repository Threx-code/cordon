// fixture: a tool that removes one note and requires a confirm argument (go)
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
	s.AddTool(mcp.NewTool("delete_note", mcp.WithDescription("Delete one note after confirmation."), mcp.WithBoolean("confirm", mcp.Required())), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if req.Params.Arguments["confirm"] != true {
			return mcp.NewToolResultError("confirmation is required"), nil
		}
		return mcp.NewToolResultText("deleted"), nil
	})
}
