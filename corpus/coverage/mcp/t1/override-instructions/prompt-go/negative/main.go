// fixture: a plain description of a lookup with a previous-revision option (prompt, go)
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
	s.AddPrompt(mcp.NewPrompt("review"), func(ctx context.Context, req mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
		return mcp.NewGetPromptResult("review", []mcp.PromptMessage{mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent("Looks up a note by id and returns the text and the time it was last edited; pass previous=true for the earlier revision."))}), nil
	})
}
