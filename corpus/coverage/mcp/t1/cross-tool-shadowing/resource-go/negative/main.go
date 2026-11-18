// fixture: a description that names another of its own tools as the first step (resource, go)
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
		return []mcp.ResourceContents{mcp.TextResourceContents{URI: "notes://today", Text: "Saves a note. Call list_notes first to find the note id, then call this tool with it."}}, nil
	})
}
