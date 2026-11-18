// fixture: a plain description of a lookup with a previous-revision option (error, go)
package main

import (
	"context"
	"errors"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var _ = errors.New

func lookup(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if req.Params.Name == "" {
		return nil, errors.New("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision.")
	}
	return mcp.NewToolResultText("note"), nil
}

func main() {
	s := server.NewMCPServer("notes-server", "1.0.0")
	s.AddTool(mcp.NewTool("lookup_note", mcp.WithDescription("Look up a note."), mcp.WithString("id", mcp.Required())), lookup)
}
