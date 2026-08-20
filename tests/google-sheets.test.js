import assert from "node:assert/strict";
import { googleSheetsTestHooks, GOOGLE_SHEETS_SCOPE } from "../google-sheets.js";

const {
  buildContactExportRows,
  createGoogleSheetsAuthURL,
  exportHash,
  encryptRefreshToken,
  decryptRefreshToken,
  GOOGLE_SHEETS_CELL_LIMIT
} = googleSheetsTestHooks;

function makeContact(overrides = {}) {
  const history = {
    Notes: "08/12/2026 3:41 PM | Jared\nCustomer wants exterior only next time.",
    "Scheduled Jobs": "job_1 | Exterior Window Cleaning | Scheduled | 08/20/2026 9:00 AM - 11:00 AM | $475.00",
    "Completed Jobs": "job_0 | Interior Window Cleaning | Completed | 07/10/2026 9:00 AM - 11:00 AM | $350.00",
    Quotes: "Quote #184 | Accepted | $475.00 | 08/10/2026\nExterior Window Cleaning | 1 x $350.00 = $350.00\nScreen Cleaning | 5 x $25.00 = $125.00",
    "SMS Messages": "08/14/2026 4:32 PM | OUT | Delivered | +15025550100\nHey Jane, we're headed your way.",
    Calls: "08/14/2026 4:10 PM | OUT | completed | +15025550100 | 300s",
    "Activity Log": "08/10/2026 12:00 PM | quote.created | Jared\nCreated quote #184",
    ...(overrides.history || {})
  };
  return {
    contact: {
      id: "11111111-1111-4111-8111-111111111111",
      name: "Jane Doe",
      company_name: "Doe Windows",
      phone: "+15025550100",
      email: "jane@example.com",
      address: "123 Main St, Louisville, KY 40202",
      contact_type: "customer",
      tags: "vip, residential",
      created_at: "2023-02-01T15:00:00.000Z",
      updated_at: "2026-08-15T15:00:00.000Z",
      lead_info: ["Lead source: Previous CRM", "Needs exterior only"]
    },
    stage_name: "Estimate Sent",
    history,
    ...Object.fromEntries(Object.entries(overrides).filter(([key]) => key !== "history"))
  };
}

async function testExporterSchemaAndHistory() {
  const { schema, rows } = buildContactExportRows([makeContact()], new Date("2026-08-15T12:30:00.000Z"));
  const row = rows[0];

  assert.equal(schema.headers[0], "WolfCRM Contact ID");
  assert.equal(row[0], "11111111-1111-4111-8111-111111111111");
  assert.ok(schema.headers.indexOf("Lead Info 1") > schema.headers.indexOf("Activity Log"));
  assert.equal(row[schema.headers.indexOf("Current Stage")], "Estimate Sent");
  assert.equal(row[schema.headers.indexOf("Tags")], "residential; vip");
  assert.match(row[schema.headers.indexOf("Quotes")], /Screen Cleaning/);
  assert.match(row[schema.headers.indexOf("SMS Messages")], /OUT \| Delivered/);
  assert.match(row[schema.headers.indexOf("Calls")], /completed/);
  assert.match(row[schema.headers.indexOf("Completed Jobs")], /Completed/);
  assert.equal(row[schema.headers.indexOf("Lead Info 1")], "Lead source: Previous CRM");
}

async function testLongContinuationColumns() {
  const longText = "A".repeat(GOOGLE_SHEETS_CELL_LIMIT + 250);
  const { schema, rows } = buildContactExportRows([makeContact({ history: { "SMS Messages": longText } })], new Date("2026-08-15T12:30:00.000Z"));
  assert.ok(schema.headers.includes("SMS Messages 2"));
  const reconstructed = rows[0][schema.headers.indexOf("SMS Messages")] + rows[0][schema.headers.indexOf("SMS Messages 2")];
  assert.equal(reconstructed, longText);
  assert.ok(schema.headers.indexOf("Lead Info 1") > schema.headers.indexOf("SMS Messages 2"));
}

async function testExportHashChangesOnlyWhenExportedRowChanges() {
  const lastSynced = new Date("2026-08-15T12:30:00.000Z");
  const syncDates = new Map([["11111111-1111-4111-8111-111111111111", lastSynced]]);
  const first = buildContactExportRows([makeContact()], new Date("2026-08-16T12:30:00.000Z"), syncDates).rows[0];
  const second = buildContactExportRows([makeContact()], new Date("2026-08-17T12:30:00.000Z"), syncDates).rows[0];
  assert.equal(exportHash(first), exportHash(second));

  const changed = buildContactExportRows([makeContact({ history: { "SMS Messages": "08/15/2026 9:00 AM | IN\nNew message" } })], new Date("2026-08-17T12:30:00.000Z"), syncDates).rows[0];
  assert.notEqual(exportHash(first), exportHash(changed));
}

async function testOAuthURLScopeAndPicker() {
  const captured = [];
  const pool = {
    query: async (sql, params) => {
      captured.push({ sql, params });
      return { rows: [] };
    }
  };
  const result = await createGoogleSheetsAuthURL(pool, {
    companyId: "22222222-2222-4222-8222-222222222222",
    userId: "33333333-3333-4333-8333-333333333333"
  }, {
    GOOGLE_OAUTH_CLIENT_ID: "client.apps.googleusercontent.com",
    GOOGLE_OAUTH_CLIENT_SECRET: "secret",
    GOOGLE_OAUTH_REDIRECT_URI: "https://example.com/api/integrations/google-sheets/oauth/callback"
  });
  const url = new URL(result.authorization_url);
  assert.equal(url.searchParams.get("scope"), GOOGLE_SHEETS_SCOPE);
  assert.equal(url.searchParams.get("trigger_onepick"), "true");
  assert.equal(url.searchParams.get("mimetypes"), "application/vnd.google-apps.spreadsheet");
  assert.equal(url.searchParams.get("access_type"), "offline");
  assert.equal(captured.length, 1);
}

async function testCredentialEncryptionRoundTrip() {
  const env = {
    FINANCE_TOKEN_ENCRYPTION_KEY: Buffer.alloc(32, 7).toString("base64")
  };
  const encrypted = encryptRefreshToken("refresh-token-value", env);
  assert.notEqual(encrypted.refresh_token_ciphertext, "refresh-token-value");
  assert.equal(decryptRefreshToken(encrypted, env), "refresh-token-value");
}

await testExporterSchemaAndHistory();
await testLongContinuationColumns();
await testExportHashChangesOnlyWhenExportedRowChanges();
await testOAuthURLScopeAndPicker();
await testCredentialEncryptionRoundTrip();

console.log("google-sheets tests passed");
