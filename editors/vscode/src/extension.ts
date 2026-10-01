import { execFile } from "node:child_process";
import * as path from "node:path";
import * as vscode from "vscode";
import { parseReport, Severity, toDiagnostics } from "./findings";

const SEVERITY: Record<string, vscode.DiagnosticSeverity> = {
  error: vscode.DiagnosticSeverity.Error,
  warning: vscode.DiagnosticSeverity.Warning,
  information: vscode.DiagnosticSeverity.Information,
  hint: vscode.DiagnosticSeverity.Hint,
};
const SAVE_DELAY_MS = 1500;
const SCAN_TIMEOUT_MS = 5 * 60 * 1000;

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
    // Read from the machine scope only, whatever a workspace's settings say.
    const executable = settings.inspect<string>("path")?.globalValue ?? "cordon-scanner";
    const minimum = settings.get<Severity>("minimumSeverity", "low");
    diagnostics.clear();
    let total = 0;
    try {
      for (const folder of folders) {
        const root = folder.uri.fsPath;
        const stdout = await run(executable, ["scan", root, "--format", "json", "--quiet", "--no-color", "--offline"], root);
        const report = parseReport(stdout);
        const { located, general } = toDiagnostics(report, minimum);
        const byFile = new Map<string, vscode.Diagnostic[]>();
        for (const item of located) {
          const range = new vscode.Range(item.line, item.column, item.line, Number.MAX_SAFE_INTEGER);
          const diagnostic = new vscode.Diagnostic(range, item.message, SEVERITY[item.severity]);
          diagnostic.source = "Cordon";
          diagnostic.code = item.code;
          const file = path.join(root, item.path);
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
  );
  void scan();
}

function run(executable: string, args: string[], cwd: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // `execFile`, never a shell: the folder path is an argument, not part of a command line.
    execFile(executable, args, { cwd, timeout: SCAN_TIMEOUT_MS, maxBuffer: 256 * 1024 * 1024 }, (error, stdout, stderr) => {
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
