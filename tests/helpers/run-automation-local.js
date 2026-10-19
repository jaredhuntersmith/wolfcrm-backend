import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { startLocalPostgres } from "./local-postgres.js";
const fixture = startLocalPostgres();
fixture.configureEnvironment();
try {
  const url = new URL("postgresql://localhost/postgres");
  url.username = fixture.config.user;
  url.searchParams.set("host", fixture.config.host);
  const child = spawn(
    process.execPath,
    [
      fileURLToPath(
        new URL("../automation-core.integration.js", import.meta.url),
      ),
    ],
    { env: { ...process.env, TEST_DATABASE_URL: url.href }, stdio: "inherit" },
  );
  process.exitCode = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code) => resolve(code ?? 1));
  });
} finally {
  fixture.stop();
}
