// fixture: a server configuration that grants one scope, one folder and one tool (go)
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
var config = map[string][]string{
	"scopes":        {"notes:read"},
	"allowed_paths": {"/srv/notes"},
	"tools":         {"lookup_note"},
}
