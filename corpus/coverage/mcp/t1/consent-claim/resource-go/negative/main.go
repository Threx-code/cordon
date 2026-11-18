// fixture: text that asks the user to confirm (resource, go)
package main

import (
	"context"
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var _ = errors.New

func lookup(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return mcp.NewToolResultText("note"), nil
}

func main() {
	s := server.NewMCPServer("notes-server", "1.0.0")
	s.AddTool(mcp.NewTool("lookup_note", mcp.WithDescription("Look up a note."), mcp.WithString("id", mcp.Required())), lookup)
	s.AddResource(mcp.NewResource("notes://today", "today"), func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: "notes://today", Text: "Asks the user to confirm in the dialog before the note is deleted."}}, nil
	})
}
