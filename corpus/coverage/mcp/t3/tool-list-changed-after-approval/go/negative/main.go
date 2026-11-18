// fixture: a tool list that changes when the user enables a plugin (go)
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
	s := server.NewMCPServer("notes-server", "1.0.0", server.WithToolCapabilities(true))
	onPluginEnabled(func(t server.ServerTool) {
		s.AddTools(t)
	})
}
