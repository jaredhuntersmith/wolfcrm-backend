export const DESKTOP_CONTACT_FILTER_FIELDS = Object.freeze([
  "phone",
  "email",
  "address",
  "job_type",
  "tags",
  "lead_info",
  "u1",
  "u2",
  "u3",
  "u4",
  "u5"
]);

const allowedFields = new Set(DESKTOP_CONTACT_FILTER_FIELDS);

function safeAlias(alias) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) {
    throw new TypeError("Contact filters require a safe SQL alias.");
  }
  return alias;
}

function listFromQuery(value, maximum, maximumLength) {
  const raw = Array.isArray(value) ? value : value == null ? [] : [value];
  const seen = new Set();
  const result = [];
  for (const item of raw.flatMap((entry) => String(entry).split(/[;,]/))) {
    const clean = item.trim().slice(0, maximumLength);
    const key = clean.toLocaleLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    result.push(clean);
    if (result.length >= maximum) break;
  }
  return result;
}

export function parseDesktopContactListFilters(query = {}) {
  const has = listFromQuery(query.has, DESKTOP_CONTACT_FILTER_FIELDS.length, 32)
    .filter((field) => allowedFields.has(field));
  const notHas = listFromQuery(query.not_has, DESKTOP_CONTACT_FILTER_FIELDS.length, 32)
    .filter((field) => allowedFields.has(field));
  return {
    has,
    notHas,
    includeTags: listFromQuery(query.include_tag, 20, 64),
    excludeTags: listFromQuery(query.exclude_tag, 20, 64),
    groupCustomers: String(query.group_customers || "") === "1"
  };
}

function tagRows(alias) {
  const prefix = `${safeAlias(alias)}.`;
  return `regexp_split_to_table(TRIM(BOTH '{}' FROM COALESCE(${prefix}tags::text, '')), '\\s*[,;]\\s*') AS contact_tag(value)`;
}

function contactTagMatchPredicate(alias, parameter) {
  if (!/^\$\d+$/.test(parameter)) {
    throw new TypeError("Contact tag filters require a positional SQL parameter.");
  }
  return `EXISTS (
    SELECT 1
      FROM ${tagRows(alias)}
     WHERE LOWER(TRIM(BOTH '"' FROM contact_tag.value)) = LOWER(${parameter})
        OR LOWER(TRIM(BOTH '"' FROM contact_tag.value)) LIKE '%' || LOWER(${parameter}) || '%'
        OR LOWER(${parameter}) LIKE '%' || LOWER(TRIM(BOTH '"' FROM contact_tag.value)) || '%'
  )`;
}

function contactTagExactPredicate(alias, parameter) {
  if (!/^\$\d+$/.test(parameter)) {
    throw new TypeError("Contact tag filters require a positional SQL parameter.");
  }
  return `EXISTS (
    SELECT 1
      FROM ${tagRows(alias)}
     WHERE LOWER(TRIM(BOTH '"' FROM contact_tag.value)) = LOWER(${parameter})
  )`;
}

function contactFieldPresentPredicate(alias, field) {
  const prefix = `${safeAlias(alias)}.`;
  if (["phone", "email", "address", "job_type"].includes(field)) {
    return `BTRIM(COALESCE(${prefix}${field}, '')) <> ''`;
  }
  if (field === "tags") {
    return `EXISTS (SELECT 1 FROM ${tagRows(alias)} WHERE BTRIM(TRIM(BOTH '"' FROM contact_tag.value)) <> '')`;
  }
  if (field === "lead_info") {
    const legacy = ["u1", "u2", "u3", "u4", "u5"]
      .map((key) => `BTRIM(COALESCE(${prefix}${key}, '')) <> ''`)
      .join(" OR ");
    return `((${legacy}) OR EXISTS (
      SELECT 1
        FROM jsonb_array_elements_text(
          CASE WHEN jsonb_typeof(${prefix}lead_info) = 'array' THEN ${prefix}lead_info ELSE '[]'::jsonb END
        ) AS lead_info_value(value)
       WHERE BTRIM(lead_info_value.value) <> ''
    ))`;
  }
  if (/^u[1-5]$/.test(field)) {
    const index = Number(field.slice(1)) - 1;
    return `COALESCE(
      NULLIF(BTRIM(CASE WHEN jsonb_typeof(${prefix}lead_info) = 'array' THEN ${prefix}lead_info ->> ${index} END), ''),
      NULLIF(BTRIM(${prefix}${field}), '')
    ) IS NOT NULL`;
  }
  throw new TypeError(`Unsupported Contact filter field: ${field}`);
}

export function buildDesktopContactListFilters(query = {}, { alias = "c", parameterOffset = 0 } = {}) {
  safeAlias(alias);
  const filters = parseDesktopContactListFilters(query);
  const values = [];
  const predicates = [];
  const bind = (value) => {
    values.push(value);
    return `$${parameterOffset + values.length}`;
  };

  for (const field of filters.has) predicates.push(contactFieldPresentPredicate(alias, field));
  for (const field of filters.notHas) predicates.push(`NOT (${contactFieldPresentPredicate(alias, field)})`);

  if (filters.includeTags.length) {
    predicates.push(`(${filters.includeTags.map((tag) => contactTagMatchPredicate(alias, bind(tag))).join(" OR ")})`);
  }
  if (filters.excludeTags.length) {
    predicates.push(`NOT (${filters.excludeTags.map((tag) => contactTagMatchPredicate(alias, bind(tag))).join(" OR ")})`);
  }

  const customerExpression = filters.groupCustomers
    ? contactTagExactPredicate(alias, bind("won"))
    : null;
  return { ...filters, predicates, values, customerExpression };
}
