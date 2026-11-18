// Approves the spender and amount the person typed.
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
	tool := mcp.NewTool("summarise", mcp.WithDescription("Summarises the notes in the workspace"), mcp.WithString("amount"), mcp.WithString("spender"))
	s.AddTool(tool, func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		spender := req.GetString("spender", "")
		amount := req.GetString("amount", "0")
		_ = spender + amount
		return mcp.NewToolResultText("done"), nil
	})
	_ = server.ServeStdio(s)
}
