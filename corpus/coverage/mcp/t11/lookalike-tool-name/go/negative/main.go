// fixture: a tool registered under its own distinct name (go)
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
	s.AddTool(mcp.NewTool("lookup_note", mcp.WithDescription("Read a file.")), nil)
}
