import { execFile } from "node:child_process";
import * as os from "node:os";

/** The arguments of the scanner's decision command, asked from the IDE point. */
export function decideArgs(point: string = "ide"): string[] {
  return ["decide", "--point", point];
}

export interface Decision {
  state: string;
  reasonCodes: string[];
  summary: string;
}

/** What the scanner's decision command printed: the state, the reason codes and the one-line summary. */
export function parseDecision(stdout: string): Decision {
  const document: unknown = JSON.parse(stdout);
  if (typeof document !== "object" || document === null) {
    throw new Error("the decision is not an object");
  }
  const record = document as Record<string, unknown>;
  const explanation = (record.explanation ?? {}) as Record<string, unknown>;
  if (typeof record.state !== "string" || !Array.isArray(record.reason_codes)) {
    throw new Error("the answer is not a decision");
  }
  return {
    state: record.state,
    reasonCodes: record.reason_codes.map(String),
    summary: typeof explanation.summary === "string" ? explanation.summary : "",
  };
}

/**
 * Asks the scanner for a decision: the question (policy, artifact, evidence, clock, context) goes to its
 * standard input as JSON and the decision comes back on standard output. `execFile`, never a shell, and run
 * from the temp directory so a workspace cannot plant the executable.
 */
export function askDecision(executable: string, question: object, point: string = "ide"): Promise<Decision> {
  return new Promise((resolve, reject) => {
    const child = execFile(
      executable,
      decideArgs(point),
      { cwd: os.tmpdir(), timeout: 60_000, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          reject(new Error(stderr.trim() || error.message));
          return;
        }
        try {
          resolve(parseDecision(stdout));
        } catch (problem) {
          reject(problem instanceof Error ? problem : new Error(String(problem)));
        }
      },
    );
    // A scanner that exits without reading the question closes the pipe: its exit code and message say why.
    child.stdin?.on("error", () => undefined);
    child.stdin?.end(JSON.stringify(question));
  });
}
