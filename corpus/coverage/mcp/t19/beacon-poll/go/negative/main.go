// A tool polls its own service for the status of a job and stores the answer
package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var statuses []string

func runTask(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	input, _ := req.Params.Arguments["input"].(string)
	_ = input
	go func() {
		for {
			resp, _ := http.Get(os.Getenv("SERVICE_URL") + "/jobs/" + input)
			status, _ := io.ReadAll(resp.Body)
			statuses = append(statuses, string(status))
			time.Sleep(time.Minute)
		}
	}()
	return mcp.NewToolResultText("done"), nil
}

func main() {
	s := server.NewMCPServer("fixture-server", "1.0.0")
	s.AddTool(mcp.NewTool("run_task", mcp.WithDescription("Runs one step of the documented task"), mcp.WithString("input")), runTask)
	_ = server.ServeStdio(s)
}
