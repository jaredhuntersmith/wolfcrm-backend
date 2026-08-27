import assert from "node:assert/strict";
import test from "node:test";
import {
  CONTACT_UPDATE_EVENT_FIELDS,
  contactChangedFields,
  contactRequestChangedFields
} from "../contact-update-events.js";

test("the contact event field catalog covers every mutable API field", () => {
  assert.deepEqual(CONTACT_UPDATE_EVENT_FIELDS, [
    "name",
    "phone",
    "email",
    "address",
    "value_cents",
    "lat",
    "lng",
    "tags",
    "job_type",
    "u1",
    "u2",
    "u3",
    "u4",
    "u5",
    "lead_info",
    "source",
    "lead_submitted_at",
    "created_at"
  ]);
});

test("contact API updates report tags, Lead Info, and lead dates to automations", () => {
  const before = {
    tags: "{lead}",
    lead_info: ["Original answer"],
    lead_submitted_at: new Date("2026-08-20T14:00:00.000Z"),
    created_at: new Date("2026-08-20T14:05:00.000Z")
  };
  const after = {
    tags: "{lead,vip}",
    lead_info: ["Updated answer", "Second answer"],
    lead_submitted_at: new Date("2026-08-19T14:00:00.000Z"),
    created_at: new Date("2026-08-19T14:05:00.000Z")
  };

  assert.deepEqual(
    contactRequestChangedFields(before, after, {
      tags: ["lead", "vip"],
      lead_info: after.lead_info,
      lead_submitted_at: "2026-08-19T14:00:00.000Z",
      created_at: "2026-08-19T14:05:00.000Z"
    }),
    [
      { field: "tags", old_value: before.tags, new_value: after.tags },
      { field: "lead_info", old_value: before.lead_info, new_value: after.lead_info },
      { field: "lead_submitted_at", old_value: before.lead_submitted_at, new_value: after.lead_submitted_at },
      { field: "created_at", old_value: before.created_at, new_value: after.created_at }
    ]
  );
});

test("contact API updates ignore omitted and unchanged fields", () => {
  const before = { name: "Avery", phone: "5551002000", lead_info: ["Same"] };
  const after = { name: "Avery", phone: "5559990000", lead_info: ["Same"] };

  assert.deepEqual(
    contactRequestChangedFields(before, after, { name: "Avery", lead_info: ["Same"] }),
    []
  );
});

test("contact change comparison preserves explicit null transitions", () => {
  assert.deepEqual(
    contactChangedFields({ source: "Referral" }, { source: null }, ["source"]),
    [{ field: "source", old_value: "Referral", new_value: null }]
  );
});
