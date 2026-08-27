import assert from "node:assert/strict";
import test from "node:test";
import {
  CONTACT_EXPORT_HEADERS,
  buildContactExportCSV,
  buildContactExportRows,
  defaultContactExportFilename,
  escapeContactCSVCell
} from "../contact-export.js";

test("contact export matches the native shared columns and authorized enrichment shape", () => {
  const contacts = [
    {
      id: "contact-b",
      name: "Zed Customer",
      phone: "+15551234567",
      email: "customer@example.com",
      address: "1 Main St, Springfield",
      value_cents: 12345,
      lat: 40.1,
      lng: -89.6,
      tags: "{lead,vip}",
      job_type: "Window cleaning",
      u1: "Legacy answer",
      lead_info: ["Variable answer", ""],
      lead_submitted_at: "2026-08-01T13:00:00.000Z",
      created_at: "2026-08-02T14:00:00.000Z",
      updated_at: "2026-08-03T15:00:00.000Z"
    },
    { id: "contact-a", name: "Ada Customer", lead_info: null, u1: "Legacy one" }
  ];
  const quotes = [{
    id: "quote-1",
    contact_id: "contact-b",
    title: "Exterior package",
    status: "accepted",
    created_at: "2026-08-04T12:00:00.000Z",
    total_cents: 35000,
    line_items: [{ name: "Windows", qty: 2, price_cents: 17500 }],
    notes: "Customer approved"
  }];
  const completedJobs = [{
    id: "job-1",
    contact_id: "contact-b",
    title: "August service",
    start_at: "2026-08-05T14:00:00.000Z",
    finished_at: "2026-08-05T16:00:00.000Z",
    price_cents: 40000,
    service_items: [{ name: "Exterior glass", price_cents: 40000 }],
    notes: "Complete"
  }];

  const rows = buildContactExportRows({ contacts, quotes, completedJobs });
  assert.deepEqual(rows[0], CONTACT_EXPORT_HEADERS);
  assert.equal(rows[1][0], "contact-a", "contacts are name-sorted like the native exporter");

  const exported = Object.fromEntries(CONTACT_EXPORT_HEADERS.map((header, index) => [header, rows[2][index]]));
  assert.equal(exported.Value, "123.45");
  assert.equal(exported.Tags, "lead; vip");
  assert.equal(exported["Lead Info"], "Variable answer");
  assert.equal(exported.Notes, "", "device-local iPhone notes are never fabricated on the server");
  assert.equal(exported["Quote Count"], "1");
  assert.equal(exported["Quote Total"], "350.00");
  assert.match(exported["Quotes Made"], /Exterior package - accepted - 2026-08-04T12:00:00Z - 350\.00/);
  assert.match(exported["Quotes Made"], /Windows x2 175\.00/);
  assert.equal(exported["Completed Job Count"], "1");
  assert.equal(exported["Completed Job Total"], "400.00");
  assert.match(exported["Jobs Completed"], /August service - 2026-08-05T14:00:00Z - Finished 2026-08-05T16:00:00Z/);
});

test("contact export emits valid escaped CSV and neutralizes spreadsheet formulas", () => {
  assert.equal(escapeContactCSVCell('plain'), "plain");
  assert.equal(escapeContactCSVCell('A "quoted", value'), '"A ""quoted"", value"');
  assert.equal(escapeContactCSVCell("line 1\r\nline 2"), '"line 1\nline 2"');
  assert.equal(escapeContactCSVCell("=HYPERLINK(\"https://example.com\")"), '"\'=HYPERLINK(""https://example.com"")"');
  assert.equal(escapeContactCSVCell("  +1-555-1234"), "'  +1-555-1234");
  assert.equal(escapeContactCSVCell("+1 (555) 123-4567"), "+1 (555) 123-4567");
  assert.equal(escapeContactCSVCell("-89.6"), "-89.6");

  const csv = buildContactExportCSV({ contacts: [{ id: "1", name: "=CMD()" }] });
  assert.ok(csv.endsWith("\n"));
  assert.match(csv, /\n1,'=CMD\(\)/);
});

test("contact export filenames are deterministic and UTC dated", () => {
  assert.equal(defaultContactExportFilename(new Date("2026-08-27T23:59:59.000Z")), "wolfcrm-contacts-2026-08-27.csv");
});
