import { strict as assert } from "node:assert";
import { test } from "node:test";
import { containedPath, parseReport, toDiagnostics } from "../src/findings";

const report = {
  complete: true,
  findings: [
    { rule_id: "SUSPECT.DROPPER.001", severity: "high", message: "fetch then run", remediation: "pin it",
      location: { path: "innocuous/__init__.py", line: 6, column: 1 } },
    { rule_id: "POLICY.X.001", severity: "info", message: "note", location: { path: "a.py", line: 1 } },
    { rule_id: "OPERATIONAL.Y", severity: "medium", message: "whole repo", location: { path: "." } },
    { rule_id: "SUSPECT.Z.001", severity: "high", message: "inside an archive", location: { path: "pkg.tgz!package/x.js", line: 2 } },
    { rule_id: "SUSPECT.W.001", severity: "high", message: "escapes", location: { path: "../../etc/passwd", line: 1 } },
  ],
};

test("a located finding becomes a zero-based diagnostic with its fix", () => {
  const { located } = toDiagnostics(report as never, "low");
  assert.equal(located.length, 1);
  assert.deepEqual(
    { path: located[0].path, line: located[0].line, severity: located[0].severity, code: located[0].code },
    { path: "innocuous/__init__.py", line: 5, severity: "error", code: "SUSPECT.DROPPER.001" },
  );
  assert.match(located[0].message, /Fix: pin it/);
});

test("repository-wide, archive and escaping paths never become editor positions", () => {
  const { general } = toDiagnostics(report as never, "low");
  assert.deepEqual(general.map((f) => f.rule_id), ["OPERATIONAL.Y", "SUSPECT.Z.001", "SUSPECT.W.001"]);
});

test("the minimum severity filters", () => {
  const { located, general } = toDiagnostics(report as never, "high");
  assert.equal(located.length + general.length, 3);
});

test("output that is not a report is an error, never a clean result", () => {
  assert.throws(() => parseReport("{}"));
  assert.throws(() => parseReport("not json"));
});

test("a reported path never names a file outside the scanned folder", () => {
  assert.equal(containedPath("/w/repo", "src/a.py"), "/w/repo/src/a.py");
  assert.equal(containedPath("/w/repo", "../../home/u/.ssh/config"), null);
  assert.equal(containedPath("/w/repo", "/etc/passwd"), null);
  assert.equal(containedPath("/w/repo", "."), null);
  assert.equal(containedPath("/w/repo", "src/../../repo2/x"), null);
});
