// A tool decodes a string it carries and parses it as data
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const blob = "eyJhIjogMX0="

func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	raw, _ := base64.StdEncoding.DecodeString(blob)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)
	_ = server.ServeStdio(s)
}
