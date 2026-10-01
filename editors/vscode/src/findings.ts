// Cordon's JSON report, turned into plain diagnostic records. Kept free of the `vscode` module so
// it can be tested without an editor; `extension.ts` maps these onto VS Code's own types.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface ReportFinding {
  rule_id: string;
  severity: Severity;
  message: string;
  remediation?: string;
  location: { path: string; line?: number | null; column?: number | null };
}

export interface Report {
  findings: ReportFinding[];
  complete?: boolean;
}

export interface Diagnostic {
  /** Path relative to the scanned root, archive members excluded (`a.tgz!x` has no editor file). */
  path: string;
  /** Zero-based, as editors count. */
  line: number;
  column: number;
  severity: "error" | "warning" | "information" | "hint";
  code: string;
  message: string;
}

const ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

export function atLeast(severity: Severity, minimum: Severity): boolean {
  return ORDER.indexOf(severity) >= ORDER.indexOf(minimum);
}

export function editorSeverity(severity: Severity): Diagnostic["severity"] {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "low":
      return "information";
    default:
      return "hint";
  }
}

/** Findings as diagnostics. Repository-wide ones (path `.`) and archive members have no line to
 * sit on, so they are returned separately for the status bar and the output channel. */
export function toDiagnostics(
  report: Report,
  minimum: Severity,
): { located: Diagnostic[]; general: ReportFinding[] } {
  const located: Diagnostic[] = [];
  const general: ReportFinding[] = [];
  for (const finding of report.findings ?? []) {
    if (!finding || typeof finding.rule_id !== "string" || !atLeast(finding.severity, minimum)) {
      continue;
    }
    const path = finding.location?.path ?? "";
    if (!path || path === "." || path.includes("!") || path.startsWith("/") || path.split("/").includes("..")) {
      general.push(finding);
      continue;
    }
    const message = finding.remediation ? `${finding.message}\n\nFix: ${finding.remediation}` : finding.message;
    located.push({
      path,
      line: Math.max(0, (finding.location.line ?? 1) - 1),
      column: Math.max(0, (finding.location.column ?? 1) - 1),
      severity: editorSeverity(finding.severity),
      code: finding.rule_id,
      message,
    });
  }
  return { located, general };
}

/** The report from the scanner's stdout. Exit 1 means findings, not failure; anything that is not
 * a report is an error the caller shows rather than an empty, clean-looking result. */
export function parseReport(stdout: string): Report {
  const document = JSON.parse(stdout) as Report;
  if (!document || !Array.isArray(document.findings)) {
    throw new Error("the scanner's output is not a Cordon report");
  }
  return document;
}
