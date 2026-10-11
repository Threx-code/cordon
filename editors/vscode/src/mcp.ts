import * as os from "node:os";
import * as vscode from "vscode";
import { serverArgs } from "./mcpArgs";

/**
 * Cordon's MCP server, offered to the editor's AI agents (Copilot agent mode and any other agent
 * that reads VS Code's MCP servers): installing the extension is enough, no configuration file.
 *
 * `vscode.lm.registerMcpServerDefinitionProvider` arrived in VS Code 1.101. The extension still
 * installs on older editors and on forks built from them; there the API is absent and this does
 * nothing, so the types below are declared here and the API is looked up at run time rather than
 * by raising `engines.vscode` and shutting those editors out.
 */

/** The provider id; must match `contributes.mcpServerDefinitionProviders` in package.json. */
export const PROVIDER_ID = "cordon.mcpServers";

interface StdioDefinition {
  cwd?: vscode.Uri;
}
type StdioDefinitionClass = new (
  label: string,
  command: string,
  args?: string[],
  env?: Record<string, string | number | null>,
  version?: string,
) => StdioDefinition;
interface Provider {
  readonly onDidChangeMcpServerDefinitions?: vscode.Event<void>;
  provideMcpServerDefinitions(token: vscode.CancellationToken): StdioDefinition[];
}
interface McpApi {
  registerMcpServerDefinitionProvider(id: string, provider: Provider): vscode.Disposable;
}

export interface McpSettings {
  executable: string;
  enabled: boolean;
  allowOnline: boolean;
  version: string;
}

export function registerMcpServer(context: vscode.ExtensionContext, settings: () => McpSettings): boolean {
  const api = (vscode as unknown as { lm?: Partial<McpApi> }).lm;
  const Definition = (vscode as unknown as { McpStdioServerDefinition?: StdioDefinitionClass }).McpStdioServerDefinition;
  if (typeof api?.registerMcpServerDefinitionProvider !== "function" || typeof Definition !== "function") {
    return false;
  }
  const changed = new vscode.EventEmitter<void>();
  const provider: Provider = {
    onDidChangeMcpServerDefinitions: changed.event,
    provideMcpServerDefinitions: () => {
      const current = settings();
      // An untrusted folder gets no server: the agent would read it through Cordon's tools.
      if (!current.enabled || !vscode.workspace.isTrusted) {
        return [];
      }
      const folders = (vscode.workspace.workspaceFolders ?? []).map((f) => f.uri.fsPath);
      const definition = new Definition("Cordon", current.executable, serverArgs(folders, current.allowOnline), {}, current.version);
      // Started from the temp directory, never a workspace: a planted executable there is not run.
      definition.cwd = vscode.Uri.file(os.tmpdir());
      return [definition];
    },
  };
  context.subscriptions.push(
    changed,
    api.registerMcpServerDefinitionProvider(PROVIDER_ID, provider),
    vscode.workspace.onDidChangeWorkspaceFolders(() => changed.fire()),
    vscode.workspace.onDidGrantWorkspaceTrust(() => changed.fire()),
    vscode.workspace.onDidChangeConfiguration((event) => {
      if (event.affectsConfiguration("cordon")) {
        changed.fire();
      }
    }),
  );
  return true;
}
