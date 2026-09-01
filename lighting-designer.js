const MAX_DOCUMENT_BYTES = 1_000_000;
const CURRENT_SCHEMA_VERSION = 1;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class LightingInputError extends Error {
  constructor(message, code = "lighting_invalid", statusCode = 400) {
    super(message);
    this.name = "LightingInputError";
    this.code = code;
    this.statusCode = statusCode;
  }
}

const optionalText = (value, field, maxLength) => {
  if (value == null || value === "") return null;
  if (typeof value !== "string") throw new LightingInputError(`${field} must be text.`);
  const normalized = value.trim();
  if (normalized.length > maxLength) throw new LightingInputError(`${field} is too long.`);
  return normalized || null;
};

const optionalID = (value, field) => {
  const id = optionalText(value, field, 64);
  if (id && !UUID.test(id)) throw new LightingInputError(`${field} must be a valid identifier.`);
  return id;
};

export function normalizeLightingProjectInput(input, { partial = false } = {}) {
  const source = input && typeof input === "object" && !Array.isArray(input) ? input : {};
  const output = {};
  if (Object.hasOwn(source, "id")) output.id = optionalID(source.id, "Project id");
  if (!partial || Object.hasOwn(source, "name")) {
    const name = optionalText(source.name, "Project name", 160);
    if (!name) throw new LightingInputError("Project name is required.", "lighting_name_required");
    output.name = name;
  }
  for (const [key, max] of [["property_address", 500], ["source_object_key", 700], ["preview_object_key", 700], ["thumbnail_object_key", 700]]) {
    if (!partial || Object.hasOwn(source, key)) output[key] = optionalText(source[key], key, max);
  }
  for (const key of ["contact_id", "job_id"]) {
    if (!partial || Object.hasOwn(source, key)) output[key] = optionalID(source[key], key);
  }
  if (!partial || Object.hasOwn(source, "document")) output.document = validateLightingDocument(source.document);
  return output;
}

export function validateLightingDocument(document) {
  if (!document || typeof document !== "object" || Array.isArray(document)) {
    throw new LightingInputError("Lighting document is required.", "lighting_document_required");
  }
  const encoded = JSON.stringify(document);
  if (Buffer.byteLength(encoded, "utf8") > MAX_DOCUMENT_BYTES) {
    throw new LightingInputError("Lighting document is too large.", "lighting_document_too_large", 413);
  }
  if (document.schemaVersion !== CURRENT_SCHEMA_VERSION) {
    throw new LightingInputError("Unsupported lighting document version.", "lighting_schema_unsupported");
  }
  if (!Array.isArray(document.layers) || document.layers.length > 500) {
    throw new LightingInputError("Lighting document has an invalid layer list.", "lighting_layers_invalid");
  }
  for (const layer of document.layers) {
    if (!layer || typeof layer !== "object" || typeof layer.kind !== "string" || !UUID.test(layer.id || "")) {
      throw new LightingInputError("Lighting document has an invalid layer.", "lighting_layer_invalid");
    }
  }
  return document;
}

export function lightingAssetPrefix(companyID, projectID) {
  return `companies/${companyID}/lighting/${projectID}/`;
}

export function assertLightingAssetKey(companyID, projectID, value) {
  if (!value) return null;
  if (typeof value !== "string" || !value.startsWith(lightingAssetPrefix(companyID, projectID))) {
    throw new LightingInputError("Lighting asset is outside this project.", "lighting_asset_forbidden", 403);
  }
  return value;
}

export const lightingSchemaVersion = CURRENT_SCHEMA_VERSION;
