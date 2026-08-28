import assert from "node:assert/strict";
import test from "node:test";

import {
  CONTACT_IMPORT_LIMITS,
  ContactImportError,
  contactImportContactIsUnchanged,
  contactImportFingerprint,
  parseContactCSV,
  prepareContactImport
} from "../contact-import.js";

test("Contact CSV parser preserves escaped quotes and embedded newlines", () => {
  assert.deepEqual(parseContactCSV('Name,Notes\n"Jane ""JJ"" Smith","line one\nline two"\n'), [
    ["Name", "Notes"],
    ['Jane "JJ" Smith', "line one\nline two"]
  ]);
  assert.throws(() => parseContactCSV('Name\n"unfinished'), (error) => {
    assert.equal(error.code, "csv_malformed");
    return true;
  });
});

test("Contact import normalizes native headers, values, dates, tags, and Lead Info", () => {
  const csv = [
    "Full_Name,Phone Number,E-mail,Service Address,Value Cents,Lat,Lng,Labels,Service,Lead Source,Lead Date,Customer Since,Notes,Extra Info",
    'WEB-MASTER-QA-Jane,555-0100,jane@example.com,"1 Main St, Dayton, OH",45000,39.7,-84.2,"VIP; lead; vip",Windows,Previous CRM,4/18/21,2021-04-19,"device note","Gate | Two story"'
  ].join("\n");
  const result = prepareContactImport(csv, { fileName: " old crm.csv " });

  assert.equal(result.format, "header");
  assert.equal(result.file_name, "old crm.csv");
  assert.equal(result.total_rows, 1);
  assert.equal(result.notes_excluded_count, 1);
  assert.equal(result.warning_count, 1);
  assert.equal(result.rows[0].contact.value_cents, 45000);
  assert.deepEqual(result.rows[0].contact.tags, ["vip", "lead"]);
  assert.deepEqual(result.rows[0].contact.lead_info, ["Gate", "Two story"]);
  assert.equal(result.rows[0].contact.lead_submitted_at, "2021-04-18T00:00:00.000Z");
  assert.equal(result.rows[0].contact.created_at, "2021-04-19T00:00:00.000Z");
  assert.match(result.rows[0].warnings[0], /iPhone-local/);
});

test("Contact import keeps native legacy ordering and produces stable fingerprints", () => {
  const csv = "WEB-MASTER-QA-Legacy,555-0199,42 Main St,legacy@example.com,Roofing,One,Two,,,";
  const result = prepareContactImport(csv);
  assert.equal(result.format, "legacy");
  assert.equal(result.rows[0].contact.name, "WEB-MASTER-QA-Legacy");
  assert.equal(result.rows[0].contact.email, "legacy@example.com");
  assert.equal(result.rows[0].contact.address, "42 Main St");
  assert.deepEqual(result.rows[0].contact.lead_info, ["One", "Two"]);
  assert.equal(result.fingerprint, contactImportFingerprint(csv));
  assert.equal(contactImportFingerprint(`\uFEFF${csv.replaceAll("\n", "\r\n")}`), result.fingerprint);
});

test("Contact import undo accepts only the exact imported Contact version", () => {
  const imported = "2026-08-27T12:00:00.123Z";
  assert.equal(contactImportContactIsUnchanged(imported, imported), true);
  assert.equal(contactImportContactIsUnchanged(imported, "2026-08-27T12:00:01.123Z"), false);
  assert.equal(contactImportContactIsUnchanged(null, imported), false);
  assert.equal(contactImportContactIsUnchanged("invalid", imported), false);
});

test("Contact import bounds empty, oversized, and over-count payloads", () => {
  assert.throws(() => prepareContactImport("Name\n"), (error) => error instanceof ContactImportError && error.code === "csv_empty");
  const tooMany = ["Name", ...Array.from({ length: CONTACT_IMPORT_LIMITS.maximumRows + 1 }, (_, index) => `Person ${index}`)].join("\n");
  assert.throws(() => prepareContactImport(tooMany), (error) => error.code === "csv_too_many_rows");
  assert.throws(
    () => prepareContactImport(`Name\n${"x".repeat(CONTACT_IMPORT_LIMITS.maximumCellCharacters + 1)}`),
    (error) => error.code === "csv_cell_too_large" && error.details.row_number === 2
  );
});

test("Contact import rejects calendar rollovers instead of changing customer dates", () => {
  const result = prepareContactImport("Name,Lead Submitted At,Contact Created At\nInvalid dates,2021-02-31,13/40/2021");
  assert.equal(result.rows[0].contact.lead_submitted_at, null);
  assert.equal(result.rows[0].contact.created_at, null);
  assert.equal(result.warning_count, 2);
  assert.match(result.rows[0].warnings.join(" "), /Lead Submitted At was invalid/);
});
