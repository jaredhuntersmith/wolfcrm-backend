export const DESKTOP_CONTACT_SEARCH_FIELDS = Object.freeze([
  "name",
  "phone",
  "email",
  "address",
  "job_type",
  "source",
  "u1",
  "u2",
  "u3",
  "u4",
  "u5"
]);

export function buildDesktopContactSearchPredicate(parameter, alias = "c") {
  if (!/^\$\d+$/.test(parameter)) {
    throw new TypeError("Contact search requires a positional SQL parameter.");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) {
    throw new TypeError("Contact search requires a safe SQL alias.");
  }

  const prefix = `${alias}.`;
  const scalarFields = DESKTOP_CONTACT_SEARCH_FIELDS
    .map((field) => `COALESCE(${prefix}${field}, '') ILIKE ${parameter}`)
    .join(" OR ");

  return `(${scalarFields} OR EXISTS (
    SELECT 1
      FROM jsonb_array_elements_text(
        CASE
          WHEN jsonb_typeof(${prefix}lead_info) = 'array' THEN ${prefix}lead_info
          ELSE '[]'::jsonb
        END
      ) AS lead_info_value(value)
     WHERE lead_info_value.value ILIKE ${parameter}
  ))`;
}
