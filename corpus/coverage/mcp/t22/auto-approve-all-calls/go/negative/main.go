// fixture: a policy that approves one read-only tool and confirms writes and deletes (go)
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
var policy = struct {
	AutoApprove         []string
	ConfirmBeforeWrite  bool
	ConfirmBeforeDelete bool
}{[]string{"lookup_note"}, true, true}
