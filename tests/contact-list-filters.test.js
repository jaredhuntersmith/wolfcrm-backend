import assert from "node:assert/strict";
import test from "node:test";
import {
  DESKTOP_CONTACT_FILTER_FIELDS,
  buildDesktopContactListFilters,
  parseDesktopContactListFilters
} from "../contact-list-filters.js";

test("desktop Contact filters accept only bounded shared fields and tag terms", () => {
  const parsed = parseDesktopContactListFilters({
    has: "phone,lead_info,notes,phone",
    not_has: ["email", "u1", "DROP TABLE contacts"],
    include_tag: [" VIP ", "won,vip"],
    exclude_tag: "lost;legacy",
    group_customers: "1"
  });

  assert.deepEqual(parsed.has, ["phone", "lead_info"]);
  assert.deepEqual(parsed.notHas, ["email", "u1"]);
  assert.deepEqual(parsed.includeTags, ["VIP", "won"]);
  assert.deepEqual(parsed.excludeTags, ["lost", "legacy"]);
  assert.equal(parsed.groupCustomers, true);
  assert.ok(DESKTOP_CONTACT_FILTER_FIELDS.includes("u5"));
  assert.ok(!DESKTOP_CONTACT_FILTER_FIELDS.includes("notes"));
});

test("desktop Contact filter SQL keeps values bound and covers shared field presence", () => {
  const result = buildDesktopContactListFilters({
    has: "phone,tags,lead_info,u3",
    not_has: "address",
    include_tag: ["vip", "won"],
    exclude_tag: "lost",
    group_customers: "1"
  }, { alias: "c", parameterOffset: 2 });

  assert.deepEqual(result.values, ["vip", "won", "lost", "won"]);
  assert.match(result.predicates.join(" "), /BTRIM\(COALESCE\(c\.phone, ''\)\) <> ''/);
  assert.match(result.predicates.join(" "), /regexp_split_to_table/);
  assert.match(result.predicates.join(" "), /jsonb_array_elements_text/);
  assert.match(result.predicates.join(" "), /c\.lead_info ->> 2/);
  assert.match(result.predicates.join(" "), /LOWER\(\$3\)/);
  assert.match(result.predicates.join(" "), /LOWER\(\$5\)/);
  assert.match(result.predicates.join(" "), /LIKE '%' \|\| LOWER\(\$3\) \|\| '%'/);
  assert.match(result.customerExpression, /LOWER\(\$6\)/);
  assert.doesNotMatch(result.customerExpression, /LIKE/);
  assert.doesNotMatch(result.predicates.join(" "), /vip|lost/);
});

test("desktop Contact filter SQL rejects unsafe aliases", () => {
  assert.throws(
    () => buildDesktopContactListFilters({ has: "phone" }, { alias: "c; DELETE FROM contacts" }),
    /safe SQL alias/
  );
});
