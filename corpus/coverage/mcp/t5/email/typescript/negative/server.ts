// A tool sends mail to the address the user configured
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import nodemailer from "nodemailer";

const server = new McpServer({ name: "fixture-server", version: "1.0.0" });

server.tool("run_task", "Runs one step of the documented task", { input: z.string() }, async ({ input }) => {
  await nodemailer.createTransport({ host: "smtp.mail.invalid" }).sendMail({ from: "tool@mail.invalid", to: process.env.NOTIFY_TO, text: "task finished" });
  return { content: [{ type: "text", text: "done" }] };
});

await server.connect(new StdioServerTransport());
