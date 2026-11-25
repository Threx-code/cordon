import { strict as assert } from "node:assert";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { askDecision, decideArgs, parseDecision } from "../src/decide";

const DECISION = {
  state: "BLOCK",
  reason_codes: ["R400"],
  explanation: { summary: "a known malicious package", reasons: [] },
};

test("the IDE asks at its own point", () => {
  assert.deepEqual(decideArgs(), ["decide", "--point", "ide"]);
  assert.deepEqual(decideArgs("cli"), ["decide", "--point", "cli"]);
});

test("a decision is read as its state, reason codes and summary", () => {
  assert.deepEqual(parseDecision(JSON.stringify(DECISION)), {
    state: "BLOCK",
    reasonCodes: ["R400"],
    summary: "a known malicious package",
  });
});

test("an answer that is not a decision is refused", () => {
  assert.throws(() => parseDecision("{}"), /not a decision/);
  assert.throws(() => parseDecision("[1]"), /not a decision|not an object/);
});

test("the question reaches the scanner on its input and the decision comes back", async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "cordon-decide-"));
  const script = path.join(dir, "fake-scanner");
  // Echoes the arguments it was given and the question it read, inside the decision's summary.
  writeFileSync(
    script,
    `#!/usr/bin/env node
let input = "";
process.stdin.on("data", (chunk) => (input += chunk));
process.stdin.on("end", () => {
  const question = JSON.parse(input);
  process.stdout.write(JSON.stringify({ state: "ALLOW", reason_codes: ["R100"], explanation: { summary: process.argv.slice(2).join(" ") + " " + question.artifact } }));
});
`,
  );
  chmodSync(script, 0o755);
  const decision = await askDecision(script, { artifact: "pkg:npm/left-pad" });
  assert.equal(decision.state, "ALLOW");
  assert.equal(decision.summary, "decide --point ide pkg:npm/left-pad");
});

test("a scanner that fails is an error carrying what it said", async () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "cordon-decide-"));
  const script = path.join(dir, "failing-scanner");
  writeFileSync(script, "#!/bin/sh\necho 'the question is not readable' >&2\nexit 3\n");
  chmodSync(script, 0o755);
  await assert.rejects(askDecision(script, {}), /not readable/);
});
