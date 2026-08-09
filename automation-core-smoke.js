const url = process.env.TEST_DATABASE_URL;
if (!url) {
  console.log("SKIP: TEST_DATABASE_URL is not set.");
  process.exit(0);
}

if (!/test|local|dev/i.test(url)) {
  console.error("REFUSE: TEST_DATABASE_URL must identify a test/local/dev database.");
  process.exit(2);
}

const { default: pg } = await import("pg");
const { Pool } = pg;
const pool = new Pool({ connectionString: url });

async function scalar(sql, params = []) {
  const { rows } = await pool.query(sql, params);
  return rows[0];
}

try {
  const version = await scalar("SELECT current_database() AS database, current_user AS user_name");
  const tables = await scalar(`
    SELECT
      to_regclass('public.automation_events') AS automation_events,
      to_regclass('public.automation_runs') AS automation_runs,
      to_regclass('public.automation_versions') AS automation_versions,
      to_regclass('public.contacts') AS contacts,
      to_regclass('public.opportunities') AS opportunities,
      to_regclass('public.todo_tasks') AS todo_tasks
  `);
  const missing = Object.entries(tables).filter(([, value]) => !value).map(([key]) => key);
  if (missing.length) {
    console.error(`FAIL: missing required tables: ${missing.join(", ")}`);
    process.exit(1);
  }
  console.log(`PASS: connected to ${version.database} as ${version.user_name}; core automation tables exist.`);
} finally {
  await pool.end();
}
