import assert from "node:assert/strict";
import test from "node:test";
import {
  DESKTOP_CONTACT_SEARCH_FIELDS,
  buildDesktopContactSearchPredicate
} from "../contact-search.js";

test("desktop contact search covers every scalar field in the shared contract", () => {
  const predicate = buildDesktopContactSearchPredicate("$2", "c");

  for (const field of DESKTOP_CONTACT_SEARCH_FIELDS) {
    assert.match(predicate, new RegExp(`COALESCE\\(c\\.${field}, ''\\) ILIKE \\$2`));
  }
});

test("desktop contact search safely searches each variable Lead Info value", () => {
  const predicate = buildDesktopContactSearchPredicate("$4", "contact_row");

  assert.match(predicate, /jsonb_array_elements_text/);
  assert.match(predicate, /jsonb_typeof\(contact_row\.lead_info\) = 'array'/);
  assert.match(predicate, /lead_info_value\.value ILIKE \$4/);
  assert.match(predicate, /ELSE '\[\]'::jsonb/);
});

test("desktop contact search accepts only internal SQL identifiers", () => {
  assert.throws(() => buildDesktopContactSearchPredicate("needle", "c"), /positional SQL parameter/);
  assert.throws(() => buildDesktopContactSearchPredicate("$2", "c; DROP TABLE contacts"), /safe SQL alias/);
});
