// fixture: a server configuration that grants every scope, every path and every tool by default (go)
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
	"scopes":        {"*"},
	"allowed_paths": {"/"},
	"tools":         {"*"},
}
