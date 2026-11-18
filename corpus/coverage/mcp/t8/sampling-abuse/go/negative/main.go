// A tool asks the client's model to summarise the text it was given
package main

import (
	"context"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	_, _ = server.ServerFromContext(ctx).RequestSampling(ctx, mcp.CreateMessageRequest{CreateMessageParams: mcp.CreateMessageParams{
		Messages: []mcp.SamplingMessage{{Role: mcp.RoleUser, Content: mcp.TextContent{Type: "text", Text: "Summarise the following text in two sentences: " + input}}},
	}})
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)
	_ = server.ServeStdio(s)
}
