// Run the package's complete test script with each Node test file serialized.
// Useful when several isolated worktrees share one development machine.
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url)));
for (const entry of pkg.scripts.test.split(/\s*&&\s*/)) {
  const name = entry.replace(/^npm run /, "");
  const command = pkg.scripts[name].replace(/node --test\b/g, "node --test --test-concurrency=1");
  console.log("\nSERIAL PACKAGE SCRIPT " + name + "\n" + command);
  const result = spawnSync(command, { shell: true, stdio: "inherit", env: process.env });
  if (result.status !== 0) {
    console.error("FAILED PACKAGE SCRIPT " + name);
    process.exit(result.status || 1);
  }
}
console.log("ALL PACKAGE TEST SCRIPTS PASSED");
