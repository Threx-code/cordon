/** The arguments Cordon's MCP server is started with: every workspace folder is a root it may
 * read, and the network only when the machine-scoped setting allows it. No `vscode` import, so
 * the tests run under plain Node. */
export function serverArgs(folders: readonly string[], allowOnline: boolean): string[] {
  const args = ["mcp"];
  for (const folder of folders) {
    args.push("--root", folder);
  }
  if (allowOnline) {
    args.push("--allow-online");
  }
  return args;
}
