export const CONTACT_UPDATE_EVENT_FIELDS = Object.freeze([
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

export function contactChangedFields(before, after, fields) {
  return fields
    .map((field) => ({
      field,
      old_value: before?.[field] ?? null,
      new_value: after?.[field] ?? null
    }))
    .filter((item) => JSON.stringify(item.old_value) !== JSON.stringify(item.new_value));
}

export function contactRequestChangedFields(before, after, requestBody) {
  const body = requestBody && typeof requestBody === "object" ? requestBody : {};
  const requestedFields = CONTACT_UPDATE_EVENT_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(body, field)
  );
  return contactChangedFields(before, after, requestedFields);
}
