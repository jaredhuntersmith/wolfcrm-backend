import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { join } from "node:path";
import { userInfo } from "node:os";

// A disposable Unix-socket-only cluster. Never reads DATABASE_URL or connects
// to an existing PostgreSQL server. Requires local initdb and pg_ctl binaries.
export function startLocalPostgres() {
  const root = mkdtempSync("/tmp/wolfcrm-test-pg-");
  const data = join(root, "data");
  const socket = join(root, "socket");
  mkdirSync(socket);
  const run = (command, args) => {
    const result = spawnSync(command, args, { encoding: "utf8", timeout: 30000 });
    if (result.error || result.status !== 0) throw new Error(`${command} failed: ${result.error?.message || result.stderr || result.stdout}`);
  };
  try {
    run("initdb", ["-D", data, "--auth=trust", "--no-locale", "--encoding=UTF8"]);
    run("pg_ctl", ["-D", data, "-l", join(root, "postgres.log"), "-o", `-k ${socket} -h '' -F`, "-w", "start"]);
  } catch (error) {
    rmSync(root, { recursive: true, force: true });
    throw error;
  }
  return {
    config: { host: socket, port: 5432, user: userInfo().username, database: "postgres", ssl: false },
    configureEnvironment() {
      delete process.env.DATABASE_URL;
      process.env.PGHOST = socket;
      process.env.PGPORT = "5432";
      process.env.PGUSER = userInfo().username;
      process.env.PGDATABASE = "postgres";
      process.env.DB_SSL = "false";
      process.env.OWNER_EMAIL = "";
      process.env.WOLFCRM_SKIP_SERVER_START = "true";
    },
    stop() {
      run("pg_ctl", ["-D", data, "-m", "immediate", "-w", "stop"]);
      rmSync(root, { recursive: true, force: true });
    }
  };
}
