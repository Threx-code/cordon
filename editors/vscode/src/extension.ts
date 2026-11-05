import { execFile } from "node:child_process";
import * as os from "node:os";
import * as vscode from "vscode";
import { containedPath, parseReport, Severity, toDiagnostics } from "./findings";
import { registerMcpServer } from "./mcp";

const SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};
const SAVE_DELAY_MS = 1500;
const SCAN_TIMEOUT_MS = 5 * 60 * 1000;
const INSTALL_COMMAND = "pipx install cordon-scanner";
const GUIDE = "https://github.com/Threx-code/cordon#install";

/** The scanner to run: read from the machine scope only, whatever a workspace's settings say. */
function executable(): string {
  return vscode.workspace.getConfiguration("cordon").inspect<string>("path")?.globalValue ?? "cordon-scanner";
}

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection("cordon");
  const output = vscode.window.createOutputChannel("Cordon");
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
  status.command = "cordon.scanWorkspace";
  context.subscriptions.push(diagnostics, output, status);

  let pending: NodeJS.Timeout | undefined;
  let running = false;

  const scan = async (): Promise<void> => {
    // A scanner process over an untrusted folder waits for trust; see `untrustedWorkspaces`.
    if (!vscode.workspace.isTrusted || running) {
      return;
    }
    const folders = vscode.workspace.workspaceFolders ?? [];
    if (folders.length === 0) {
      return;
    }
    running = true;
    status.text = "$(sync~spin) Cordon";
    status.show();
    const settings = vscode.workspace.getConfiguration("cordon");
    const minimum = settings.get<Severity>("minimumSeverity", "low");
    diagnostics.clear();
    let total = 0;
    try {
      for (const folder of folders) {
        const root = folder.uri.fsPath;
        const stdout = await run(executable(), ["scan", root, "--format", "json", "--quiet", "--no-color", "--offline"]);
        const report = parseReport(stdout);
        const { located, general } = toDiagnostics(report, minimum);
        const byFile = new Map<string, vscode.Diagnostic[]>();
        for (const item of located) {
          const range = new vscode.Range(item.line, item.column, item.line, Number.MAX_SAFE_INTEGER);
          const diagnostic = new vscode.Diagnostic(range, item.message, SEVERITY[item.severity]);
          diagnostic.source = "Cordon";
          diagnostic.code = item.code;
          const file = containedPath(root, item.path);
          if (file === null) {
            output.appendLine(`[${item.severity}] ${item.code} ${item.path}: outside the workspace folder; not marked`);
            continue;
          }
          byFile.set(file, [...(byFile.get(file) ?? []), diagnostic]);
        }
        for (const [file, list] of byFile) {
          diagnostics.set(vscode.Uri.file(file), list);
        }
        for (const finding of general) {
          output.appendLine(`[${finding.severity}] ${finding.rule_id} ${finding.location?.path ?? ""}: ${finding.message}`);
        }
        if (report.complete === false) {
          output.appendLine(`${folder.name}: the scan was incomplete; see the operational findings above.`);
        }
        total += located.length + general.length;
      }
      status.text = total ? `$(warning) Cordon: ${total}` : "$(shield) Cordon";
      status.tooltip = "Cordon findings in this workspace. Click to rescan.";
    } catch (error) {
      status.text = "$(error) Cordon";
      status.tooltip = String(error);
      output.appendLine(`scan failed: ${String(error)}`);
    } finally {
      running = false;
    }
  };

  context.subscriptions.push(
    vscode.commands.registerCommand("cordon.scanWorkspace", scan),
    vscode.commands.registerCommand("cordon.clear", () => diagnostics.clear()),
    vscode.workspace.onDidSaveTextDocument(() => {
      if (!vscode.workspace.getConfiguration("cordon").get<boolean>("scanOnSave", true)) {
        return;
      }
      if (pending) {
        clearTimeout(pending);
      }
      pending = setTimeout(() => void scan(), SAVE_DELAY_MS);
    }),
    vscode.workspace.onDidGrantWorkspaceTrust(() => void scan()),
    vscode.commands.registerCommand("cordon.showMcpConfig", () => showMcpConfig(output)),
  );

  void installed().then((version) => {
    if (version === null) {
      void offerInstall();
      return;
    }
    output.appendLine(`using ${version}`);
    const offered = registerMcpServer(context, () => {
      const settings = vscode.workspace.getConfiguration("cordon");
      return {
        executable: executable(),
        enabled: settings.get<boolean>("mcp.enabled", true),
        // Machine scope only, as the executable is: a repository cannot turn the network on.
        allowOnline: settings.inspect<boolean>("mcp.allowOnline")?.globalValue ?? false,
        version: version.split(" ").pop() ?? "",
      };
    });
    output.appendLine(
      offered
        ? "Cordon's MCP server is offered to this editor's AI agents (Copilot agent mode and others)."
        : "This editor has no MCP server API (VS Code 1.101+); run `Cordon: Show MCP configuration` to add it by hand.",
    );
    void scan();
  });
}

/** `cordon-scanner --version`, or null when the scanner cannot be run. */
function installed(): Promise<string | null> {
  return new Promise((resolve) => {
    execFile(executable(), ["--version"], { cwd: os.tmpdir(), timeout: 30_000 }, (error, stdout) => {
      resolve(error ? null : stdout.trim() || null);
    });
  });
}

async function offerInstall(): Promise<void> {
  const choice = await vscode.window.showWarningMessage(
    `Cordon needs the cordon-scanner command. Install it with: ${INSTALL_COMMAND}`,
    "Copy command",
    "Open guide",
  );
  if (choice === "Copy command") {
    await vscode.env.clipboard.writeText(INSTALL_COMMAND);
  } else if (choice === "Open guide") {
    await vscode.env.openExternal(vscode.Uri.parse(GUIDE));
  }
}

async function showMcpConfig(output: vscode.OutputChannel): Promise<void> {
  try {
    const text = await run(executable(), ["mcp", "config", "--client", "vscode"]);
    const document = await vscode.workspace.openTextDocument({ content: text, language: "jsonc" });
    await vscode.window.showTextDocument(document);
  } catch (error) {
    output.appendLine(`could not print the MCP configuration: ${String(error)}`);
  }
}

function run(executable: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    // `execFile`, never a shell: the folder path is an argument, not part of a command line.
    // Run from the system temp directory, never the workspace: on Windows a bare command name is
    // looked up in the working directory first, so a workspace could plant `cordon-scanner.exe`.
    execFile(executable, args, { cwd: os.tmpdir(), timeout: SCAN_TIMEOUT_MS, maxBuffer: 256 * 1024 * 1024 }, (error, stdout, stderr) => {
      // Exit 1 is "findings at or above the gate", which is a successful scan.
      const code: unknown = error ? (error as { code?: unknown }).code : undefined;
      if (error && code !== 1) {
        reject(new Error(stderr.trim() || error.message));
        return;
      }
      resolve(stdout);
    });
  });
}

export function deactivate(): void {}
