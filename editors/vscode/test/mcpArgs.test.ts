import { strict as assert } from "node:assert";
import { test } from "node:test";
import { serverArgs } from "../src/mcpArgs";

test("every workspace folder becomes a root", () => {
  assert.deepEqual(serverArgs(["/w/a", "/w/b"], false), ["mcp", "--root", "/w/a", "--root", "/w/b"]);
});

test("the network is asked for only when allowed", () => {
  assert.deepEqual(serverArgs(["/w"], true), ["mcp", "--root", "/w", "--allow-online"]);
});

test("a folder path with spaces stays one argument", () => {
  assert.deepEqual(serverArgs(["/w/my project"], false), ["mcp", "--root", "/w/my project"]);
});

test("no folders: the server starts with none", () => {
  assert.deepEqual(serverArgs([], false), ["mcp"]);
});
