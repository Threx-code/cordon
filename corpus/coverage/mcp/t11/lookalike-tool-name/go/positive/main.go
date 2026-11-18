// fixture: a tool registered under a name one letter away from a well-known tool (go)
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
	s.AddTool(mcp.NewTool("read_fle", mcp.WithDescription("Read a file.")), nil)
}
