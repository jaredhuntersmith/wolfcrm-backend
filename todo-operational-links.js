export class TodoOperationalLinkError extends Error {
  constructor(code, message, statusCode = 400) {
    super(message);
    this.name = "TodoOperationalLinkError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

const fields = [
  "linked_equipment_id",
  "linked_equipment_request_id",
  "linked_inventory_count_id",
];

function optionalIdentifier(value, field) {
  if (value == null || value === "") return null;
  if (typeof value !== "string") {
    throw new TodoOperationalLinkError("task_operational_link_invalid", `${field} must be a string or null.`);
  }
  const normalized = value.trim();
  if (!normalized) return null;
  if (normalized.length > 200) {
    throw new TodoOperationalLinkError("task_operational_link_invalid", `${field} is too long.`);
  }
  return normalized;
}

export function normalizeTaskOperationalLinks(body = {}, previous = null) {
  return Object.fromEntries(fields.map((field) => {
    const supplied = Object.prototype.hasOwnProperty.call(body, field);
    return [field, optionalIdentifier(supplied ? body[field] : previous?.[field] ?? null, field)];
  }));
}

export async function validateTaskOperationalLinks(queryable, companyID, links) {
  if (!fields.some((field) => links[field])) return links;
  if (!companyID) {
    throw new TodoOperationalLinkError("company_required", "A company is required to link operational records.", 403);
  }
  const { rows } = await queryable.query(
    `SELECT
       CASE WHEN $2::text IS NULL THEN true ELSE EXISTS(
         SELECT 1 FROM inventory_items
          WHERE company_id = $1 AND id = $2
            AND (item_type = 'equipment' OR tracking_mode IN ('asset', 'permanent'))
       ) END AS equipment_exists,
       CASE WHEN $3::text IS NULL THEN true ELSE EXISTS(
         SELECT 1 FROM equipment_requests WHERE company_id = $1 AND id = $3
       ) END AS request_exists,
       CASE WHEN $4::text IS NULL THEN true ELSE EXISTS(
         SELECT 1 FROM inventory_count_submissions WHERE company_id = $1 AND id = $4
       ) END AS count_exists`,
    [companyID, links.linked_equipment_id, links.linked_equipment_request_id, links.linked_inventory_count_id]
  );
  const result = rows[0] || {};
  if (!result.equipment_exists) {
    throw new TodoOperationalLinkError("linked_equipment_not_found", "Linked equipment was not found in this company.", 404);
  }
  if (!result.request_exists) {
    throw new TodoOperationalLinkError("linked_equipment_request_not_found", "Linked equipment request was not found in this company.", 404);
  }
  if (!result.count_exists) {
    throw new TodoOperationalLinkError("linked_inventory_count_not_found", "Linked inventory count was not found in this company.", 404);
  }
  return links;
}
