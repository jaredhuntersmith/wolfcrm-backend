import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import pg from "pg";
import { installReceiptSchema } from "../finance-receipts.js";

const { Pool } = pg;
const connectionString = process.env.TEST_DATABASE_URL;

function refuse(message) {
  console.error(`REFUSED finance receipt schema integration test: ${message}`);
  process.exit(2);
}

if (!connectionString) refuse("TEST_DATABASE_URL is required.");
if (process.env.DATABASE_URL && process.env.DATABASE_URL !== connectionString) {
  refuse("DATABASE_URL must be unset or identical to TEST_DATABASE_URL.");
}
if (!/test|local|dev|localhost|127\.0\.0\.1/i.test(connectionString)) {
  refuse("TEST_DATABASE_URL must clearly identify a local/test database.");
}
if (/railway|render|supabase|neon|amazonaws|prod|production/i.test(connectionString)) {
  refuse("hosted or production-looking databases are forbidden.");
}

const pool = new Pool({ connectionString, ssl: false });
const schemas = [];

function identifier(value) {
  if (!/^[a-z][a-z0-9_]*$/.test(value)) throw new Error(`unsafe identifier: ${value}`);
  return `"${value}"`;
}

async function createSchema(label) {
  const schema = `receipt_schema_${label}_${randomUUID().replaceAll("-", "")}`;
  schemas.push(schema);
  await pool.query(`CREATE SCHEMA ${identifier(schema)}`);
  return schema;
}

async function inSchema(schema, work) {
  const client = await pool.connect();
  try {
    await client.query(`SET search_path TO ${identifier(schema)}, public`);
    return await work(client);
  } finally {
    client.release();
  }
}

async function createPrerequisites(client, transactionIndexDefinition = "") {
  await client.query(`
    CREATE TABLE companies (id UUID PRIMARY KEY);
    CREATE TABLE users (id UUID PRIMARY KEY, company_id UUID REFERENCES companies(id));
    CREATE TABLE finance_transactions (
      id UUID PRIMARY KEY,
      company_id UUID NOT NULL REFERENCES companies(id)
    );
    ${transactionIndexDefinition}
  `);
}

async function createPartiallyMigratedReceiptTable(client, indexDefinition, transactionIndexDefinition = "") {
  await createPrerequisites(client, transactionIndexDefinition);
  await client.query(`
    CREATE TABLE finance_receipts (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id),
      transaction_id UUID,
      status TEXT NOT NULL DEFAULT 'unmatched',
      source TEXT NOT NULL DEFAULT 'ios',
      merchant_name TEXT,
      purchase_date DATE,
      content_sha256 TEXT,
      archived_at TIMESTAMPTZ
    );
    ${indexDefinition}
  `);
  const companyID = randomUUID();
  const receiptID = randomUUID();
  await client.query("INSERT INTO companies(id) VALUES($1)", [companyID]);
  await client.query(
    "INSERT INTO finance_receipts(id, company_id, merchant_name) VALUES($1,$2,'preserve-me')",
    [receiptID, companyID]
  );
  return { companyID, receiptID };
}

async function exactCompositeUniqueIndexCount(client, tableName) {
  const result = await client.query(`
    SELECT count(*)::INTEGER AS count
      FROM pg_index candidate
     WHERE candidate.indrelid=$1::REGCLASS
       AND candidate.indisunique AND candidate.indisvalid AND candidate.indisready
       AND candidate.indpred IS NULL AND candidate.indexprs IS NULL
       AND candidate.indnkeyatts=2
       AND (
         SELECT array_agg(attribute.attname::TEXT ORDER BY key_column.ordinality)
           FROM unnest(candidate.indkey::SMALLINT[]) WITH ORDINALITY
                AS key_column(attnum, ordinality)
           JOIN pg_attribute attribute
             ON attribute.attrelid=candidate.indrelid AND attribute.attnum=key_column.attnum
          WHERE key_column.ordinality <= candidate.indnkeyatts
       ) = ARRAY['company_id','id']::TEXT[]
  `, [tableName]);
  return result.rows[0].count;
}

async function assertReceiptPreserved(client, fixture) {
  const preserved = await client.query(
    "SELECT merchant_name FROM finance_receipts WHERE id=$1 AND company_id=$2",
    [fixture.receiptID, fixture.companyID]
  );
  assert.deepEqual(preserved.rows, [{ merchant_name: "preserve-me" }]);
}

try {
  const freshSchema = await createSchema("fresh");
  await inSchema(freshSchema, async (client) => {
    await createPrerequisites(client);
    await installReceiptSchema(client);
    const companyID = randomUUID();
    const receiptID = randomUUID();
    await client.query("INSERT INTO companies(id) VALUES($1)", [companyID]);
    await client.query(
      "INSERT INTO finance_receipts(id, company_id, merchant_name) VALUES($1,$2,'preserve-me')",
      [receiptID, companyID]
    );
    await installReceiptSchema(client);
    assert.equal(await exactCompositeUniqueIndexCount(client, "finance_receipts"), 1);
    assert.equal(await exactCompositeUniqueIndexCount(client, "finance_transactions"), 1);
    await assertReceiptPreserved(client, { companyID, receiptID });
  });

  const equivalentSchema = await createSchema("equivalent_index");
  await inSchema(equivalentSchema, async (client) => {
    const fixture = await createPartiallyMigratedReceiptTable(
      client,
      "CREATE UNIQUE INDEX finance_receipts_company_id_id_unique ON finance_receipts(company_id, id);",
      "CREATE UNIQUE INDEX finance_transactions_company_id_idx ON finance_transactions(company_id, id);"
    );
    await installReceiptSchema(client);
    await installReceiptSchema(client);
    assert.equal(await exactCompositeUniqueIndexCount(client, "finance_receipts"), 1);
    assert.equal(await exactCompositeUniqueIndexCount(client, "finance_transactions"), 1);
    const namedConstraint = await client.query(`
      SELECT 1 FROM pg_constraint
       WHERE conrelid='finance_receipts'::REGCLASS
         AND conname='finance_receipts_company_id_id_unique'
    `);
    assert.equal(namedConstraint.rowCount, 0);
    await assertReceiptPreserved(client, fixture);
  });

  const collisionSchema = await createSchema("name_collision");
  await inSchema(collisionSchema, async (client) => {
    const fixture = await createPartiallyMigratedReceiptTable(
      client,
      "CREATE INDEX finance_receipts_company_id_id_unique ON finance_receipts(merchant_name);",
      "CREATE INDEX finance_transactions_company_id_idx ON finance_transactions(company_id);"
    );
    await installReceiptSchema(client);
    await installReceiptSchema(client);
    assert.equal(await exactCompositeUniqueIndexCount(client, "finance_receipts"), 1);
    assert.equal(await exactCompositeUniqueIndexCount(client, "finance_transactions"), 1);
    const alternative = await client.query(`
      SELECT conname FROM pg_constraint
       WHERE conrelid='finance_receipts'::REGCLASS AND contype='u'
    `);
    assert.match(alternative.rows[0].conname, /^finance_receipts_company_id_id_key_\d+$/);
    const transactionAlternative = await client.query(`
      SELECT indexrelid::REGCLASS::TEXT AS index_name
        FROM pg_index
       WHERE indrelid='finance_transactions'::REGCLASS
         AND indisunique AND indnkeyatts=2
    `);
    assert.match(transactionAlternative.rows[0].index_name, /^finance_transactions_company_id_key_\d+$/);
    await assertReceiptPreserved(client, fixture);
  });

  console.log("PASS finance receipt schema integration (fresh, repeated, equivalent index, name collision, data preservation)");
} finally {
  for (const schema of schemas.reverse()) {
    await pool.query(`DROP SCHEMA IF EXISTS ${identifier(schema)} CASCADE`);
  }
  await pool.end();
}
