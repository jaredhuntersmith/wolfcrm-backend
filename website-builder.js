import { randomUUID } from "node:crypto";

export const WEBSITE_PROJECT_KINDS = Object.freeze([
  "website",
  "landing_page",
  "funnel",
]);

export const WEBSITE_LIFECYCLE_STATUSES = Object.freeze(["draft", "archived"]);

const PROJECT_NAME_LIMIT = 120;
const PAGE_NAME_LIMIT = 120;
const PAGE_SLUG_LIMIT = 160;
const MAX_PROJECTS_PER_COMPANY = 100;
const MAX_PAGES_PER_PROJECT = 250;
const MAX_BLOCKS_PER_PAGE = 100;
const MAX_PAGE_CONTENT_BYTES = 262144;
const SEO_TITLE_LIMIT = 70;
const SEO_DESCRIPTION_LIMIT = 200;
const MAX_NAVIGATION_ITEMS = 30;
const NAVIGATION_LABEL_LIMIT = 80;
const WEBSITE_THEME_DEFAULTS = Object.freeze({
  primary_color: "#0f766e",
  accent_color: "#f59e0b",
  background_color: "#f8fafc",
  surface_color: "#ffffff",
  text_color: "#172033",
  muted_text_color: "#64748b",
  heading_font: "modern",
  body_font: "system",
  corner_style: "rounded",
});
const WEBSITE_THEME_COLOR_FIELDS = Object.freeze([
  "primary_color",
  "accent_color",
  "background_color",
  "surface_color",
  "text_color",
  "muted_text_color",
]);
const WEBSITE_THEME_FONT_CHOICES = new Set(["system", "modern", "classic"]);
const WEBSITE_THEME_CORNER_CHOICES = new Set(["square", "soft", "rounded"]);
const WEBSITE_NAVIGATION_DEFAULTS = Object.freeze({
  mode: "automatic",
  show_brand: true,
  cta_label: "",
  cta_href: "",
  items: [],
});
const WEBSITE_BLOCK_TYPES = new Set(["hero", "text", "callout", "features", "spacer"]);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export class WebsiteBuilderError extends Error {
  constructor(code, message, statusCode = 400, details = {}) {
    super(message);
    this.name = "WebsiteBuilderError";
    this.code = code;
    this.statusCode = statusCode;
    Object.assign(this, details);
  }
}

function cleanString(value, maximumLength) {
  const text = typeof value === "string" ? value.trim() : "";
  if (text.length > maximumLength) {
    throw new WebsiteBuilderError(
      "website_field_too_long",
      `Use at most ${maximumLength} characters.`,
    );
  }
  return text;
}

function requiredName(value, label, maximumLength) {
  const name = cleanString(value, maximumLength);
  if (!name) {
    throw new WebsiteBuilderError(
      `${label.toLowerCase().replaceAll(" ", "_")}_required`,
      `${label} is required.`,
    );
  }
  return name;
}

function requiredVersion(value, field = "expected_version") {
  const parsed = typeof value === "string" && /^\d+$/.test(value.trim())
    ? Number(value.trim())
    : value;
  if (!Number.isSafeInteger(parsed) || parsed < 1) {
    throw new WebsiteBuilderError(
      "website_version_invalid",
      `${field.replaceAll("_", " ")} is invalid.`,
    );
  }
  return parsed;
}

function contentError(message) {
  return new WebsiteBuilderError("website_page_content_invalid", message);
}

function seoError(message) {
  return new WebsiteBuilderError("website_page_seo_invalid", message);
}

function themeError(message) {
  return new WebsiteBuilderError("website_project_theme_invalid", message);
}

function navigationError(message) {
  return new WebsiteBuilderError("website_project_navigation_invalid", message);
}

function assertOnlyKeys(value, allowed, label) {
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw contentError(`${label} contains an unsupported ${unknown} field.`);
}

function blockText(value, label, maximumLength, fallback = "") {
  if (value === undefined) return fallback;
  if (typeof value !== "string") throw contentError(`${label} must be text.`);
  if (value.length > maximumLength) {
    throw contentError(`${label} may be at most ${maximumLength} characters.`);
  }
  return value;
}

function blockAlignment(value) {
  if (value === undefined) return "left";
  if (value !== "left" && value !== "center") {
    throw contentError("Block alignment must be left or center.");
  }
  return value;
}

function blockLink(value) {
  const link = blockText(value, "Button link", 500).trim();
  if (!link) return "";
  if (
    (link.startsWith("/") && !link.startsWith("//") && !/\s/.test(link)) ||
    /^https?:\/\/[^\s]+$/i.test(link) ||
    /^mailto:[^\s@]+@[^\s@]+$/i.test(link) ||
    /^tel:\+?[0-9(). -]{7,30}$/i.test(link)
  ) return link;
  throw contentError("Button links must use a local path, HTTP(S), mailto, or tel address.");
}

function navigationLink(value) {
  try {
    return blockLink(value);
  } catch {
    throw navigationError("Navigation calls to action must use a local path, HTTP(S), mailto, or tel address.");
  }
}

function normalizeWebsiteBlock(value, index) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw contentError(`Block ${index + 1} must be an object.`);
  }
  assertOnlyKeys(value, new Set(["id", "type", "data"]), `Block ${index + 1}`);
  if (typeof value.id !== "string" || !UUID_PATTERN.test(value.id)) {
    throw contentError(`Block ${index + 1} has an invalid identifier.`);
  }
  if (typeof value.type !== "string" || !WEBSITE_BLOCK_TYPES.has(value.type)) {
    throw contentError(`Block ${index + 1} has an unsupported type.`);
  }
  if (!value.data || typeof value.data !== "object" || Array.isArray(value.data)) {
    throw contentError(`Block ${index + 1} properties must be an object.`);
  }
  let data;
  if (value.type === "hero" || value.type === "callout") {
    assertOnlyKeys(
      value.data,
      new Set(["heading", "body", "button_label", "button_href", "alignment"]),
      `${value.type} block`,
    );
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      body: blockText(value.data.body, "Body", 2000),
      button_label: blockText(value.data.button_label, "Button label", 80),
      button_href: blockLink(value.data.button_href),
      alignment: blockAlignment(value.data.alignment),
    };
  } else if (value.type === "text") {
    assertOnlyKeys(value.data, new Set(["heading", "body", "alignment"]), "Text block");
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      body: blockText(value.data.body, "Body", 5000),
      alignment: blockAlignment(value.data.alignment),
    };
  } else if (value.type === "features") {
    assertOnlyKeys(value.data, new Set(["heading", "items", "columns"]), "Features block");
    if (!Array.isArray(value.data.items) || value.data.items.length > 12) {
      throw contentError("Features blocks may contain up to 12 items.");
    }
    const columns = value.data.columns === undefined ? 3 : value.data.columns;
    if (![2, 3, 4].includes(columns)) {
      throw contentError("Feature columns must be 2, 3, or 4.");
    }
    data = {
      heading: blockText(value.data.heading, "Heading", 160),
      items: value.data.items.map((item, itemIndex) =>
        blockText(item, `Feature ${itemIndex + 1}`, 180).trim(),
      ),
      columns,
    };
  } else {
    assertOnlyKeys(value.data, new Set(["size"]), "Spacer block");
    const size = value.data.size === undefined ? "medium" : value.data.size;
    if (!["small", "medium", "large"].includes(size)) {
      throw contentError("Spacer size must be small, medium, or large.");
    }
    data = { size };
  }
  return { id: value.id, type: value.type, data };
}

export function normalizeWebsitePageContent(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw contentError("Page content must be a structured document.");
  }
  assertOnlyKeys(value, new Set(["schema_version", "blocks"]), "Page content");
  if (value.schema_version !== 1 || !Array.isArray(value.blocks)) {
    throw contentError("Page content must use block schema version 1.");
  }
  if (value.blocks.length > MAX_BLOCKS_PER_PAGE) {
    throw contentError(`A page may contain up to ${MAX_BLOCKS_PER_PAGE} blocks.`);
  }
  const blocks = value.blocks.map(normalizeWebsiteBlock);
  if (new Set(blocks.map((block) => block.id)).size !== blocks.length) {
    throw contentError("Every block must have a unique identifier.");
  }
  const content = { schema_version: 1, blocks };
  if (Buffer.byteLength(JSON.stringify(content), "utf8") > MAX_PAGE_CONTENT_BYTES) {
    throw contentError("Page content is too large to save.");
  }
  return content;
}

function seoText(value, label, maximumLength) {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw seoError(`${label} must be text.`);
  const text = value.trim();
  if (text.length > maximumLength) {
    throw seoError(`${label} may be at most ${maximumLength} characters.`);
  }
  return text;
}

export function normalizeWebsitePageSeo(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw seoError("SEO metadata must be an object.");
  }
  const allowed = new Set([
    "title",
    "description",
    "social_title",
    "social_description",
    "hide_from_search",
  ]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw seoError(`SEO metadata contains an unsupported ${unknown} field.`);
  if (value.hide_from_search !== undefined && typeof value.hide_from_search !== "boolean") {
    throw seoError("Search visibility must be true or false.");
  }
  return {
    title: seoText(value.title, "Search title", SEO_TITLE_LIMIT),
    description: seoText(value.description, "Search description", SEO_DESCRIPTION_LIMIT),
    social_title: seoText(value.social_title, "Social title", SEO_TITLE_LIMIT),
    social_description: seoText(value.social_description, "Social description", SEO_DESCRIPTION_LIMIT),
    hide_from_search: value.hide_from_search === true,
  };
}

function websitePageSeoPayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    title: typeof source.title === "string" ? source.title.slice(0, SEO_TITLE_LIMIT) : "",
    description: typeof source.description === "string" ? source.description.slice(0, SEO_DESCRIPTION_LIMIT) : "",
    social_title: typeof source.social_title === "string" ? source.social_title.slice(0, SEO_TITLE_LIMIT) : "",
    social_description: typeof source.social_description === "string" ? source.social_description.slice(0, SEO_DESCRIPTION_LIMIT) : "",
    hide_from_search: source.hide_from_search === true,
  };
}

export function normalizeWebsiteProjectTheme(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw themeError("Theme settings must be an object.");
  }
  const allowed = new Set([
    ...WEBSITE_THEME_COLOR_FIELDS,
    "heading_font",
    "body_font",
    "corner_style",
  ]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw themeError(`Theme settings contain an unsupported ${unknown} field.`);
  const theme = { ...WEBSITE_THEME_DEFAULTS };
  for (const field of WEBSITE_THEME_COLOR_FIELDS) {
    if (value[field] === undefined) continue;
    if (typeof value[field] !== "string" || !/^#[0-9a-f]{6}$/i.test(value[field])) {
      throw themeError(`${field.replaceAll("_", " ")} must be a six-digit hex color.`);
    }
    theme[field] = value[field].toLowerCase();
  }
  for (const field of ["heading_font", "body_font"]) {
    if (value[field] === undefined) continue;
    if (!WEBSITE_THEME_FONT_CHOICES.has(value[field])) {
      throw themeError(`${field.replaceAll("_", " ")} is unsupported.`);
    }
    theme[field] = value[field];
  }
  if (value.corner_style !== undefined) {
    if (!WEBSITE_THEME_CORNER_CHOICES.has(value.corner_style)) {
      throw themeError("Corner style is unsupported.");
    }
    theme.corner_style = value.corner_style;
  }
  return theme;
}

function websiteProjectThemePayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const compatible = Object.fromEntries(
    Object.entries(source).filter(([key]) => Object.hasOwn(WEBSITE_THEME_DEFAULTS, key)),
  );
  try {
    return normalizeWebsiteProjectTheme(compatible);
  } catch {
    return { ...WEBSITE_THEME_DEFAULTS };
  }
}

export function normalizeWebsiteProjectNavigation(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw navigationError("Navigation settings must be an object.");
  }
  const allowed = new Set(["mode", "show_brand", "cta_label", "cta_href", "items"]);
  const unknown = Object.keys(value).find((key) => !allowed.has(key));
  if (unknown) throw navigationError(`Navigation settings contain an unsupported ${unknown} field.`);
  const mode = value.mode ?? "automatic";
  if (mode !== "automatic" && mode !== "custom") {
    throw navigationError("Navigation mode must be automatic or custom.");
  }
  if (value.show_brand !== undefined && typeof value.show_brand !== "boolean") {
    throw navigationError("Brand visibility must be true or false.");
  }
  const ctaLabel = cleanString(value.cta_label, NAVIGATION_LABEL_LIMIT);
  const ctaHref = navigationLink(value.cta_href);
  if ((ctaLabel && !ctaHref) || (!ctaLabel && ctaHref)) {
    throw navigationError("Navigation call-to-action label and link must be provided together.");
  }
  const rawItems = value.items ?? [];
  if (!Array.isArray(rawItems) || rawItems.length > MAX_NAVIGATION_ITEMS) {
    throw navigationError(`Custom navigation may contain up to ${MAX_NAVIGATION_ITEMS} items.`);
  }
  const items = rawItems.map((item, index) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw navigationError(`Navigation item ${index + 1} must be an object.`);
    }
    const itemUnknown = Object.keys(item).find((key) => key !== "page_id" && key !== "label");
    if (itemUnknown) throw navigationError(`Navigation item ${index + 1} contains an unsupported ${itemUnknown} field.`);
    if (typeof item.page_id !== "string" || !UUID_PATTERN.test(item.page_id)) {
      throw navigationError(`Navigation item ${index + 1} has an invalid page identifier.`);
    }
    return {
      page_id: item.page_id,
      label: requiredName(item.label, `Navigation item ${index + 1} label`, NAVIGATION_LABEL_LIMIT),
    };
  });
  if (new Set(items.map((item) => item.page_id)).size !== items.length) {
    throw navigationError("A page may appear only once in custom navigation.");
  }
  return {
    mode,
    show_brand: value.show_brand !== false,
    cta_label: ctaLabel,
    cta_href: ctaHref,
    items: mode === "custom" ? items : [],
  };
}

function websiteProjectNavigationPayload(value) {
  const source = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const compatible = Object.fromEntries(
    Object.entries(source).filter(([key]) => Object.hasOwn(WEBSITE_NAVIGATION_DEFAULTS, key)),
  );
  try {
    return normalizeWebsiteProjectNavigation({ ...WEBSITE_NAVIGATION_DEFAULTS, ...compatible });
  } catch {
    return { ...WEBSITE_NAVIGATION_DEFAULTS, items: [] };
  }
}

function lifecycleStatus(value) {
  if (!WEBSITE_LIFECYCLE_STATUSES.includes(value)) {
    throw new WebsiteBuilderError(
      "website_status_invalid",
      "Website lifecycle status is invalid.",
    );
  }
  return value;
}

function projectKind(value) {
  if (!WEBSITE_PROJECT_KINDS.includes(value)) {
    throw new WebsiteBuilderError(
      "website_project_kind_invalid",
      "Choose Website, Landing Page, or Funnel.",
    );
  }
  return value;
}

function slugSegment(value) {
  return String(value ?? "")
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-");
}

export function normalizeWebsiteSlug(value, fallbackName = "page") {
  const raw = typeof value === "string" ? value.trim() : "";
  if (raw === "/") return "/";
  const source = raw || fallbackName;
  if (/^[a-z]+:\/\//i.test(source) || source.includes("?") || source.includes("#")) {
    throw new WebsiteBuilderError(
      "website_page_slug_invalid",
      "Use a path such as /services or /roofing/estimate.",
    );
  }
  const segments = source
    .replace(/^\/+|\/+$/g, "")
    .split("/")
    .map(slugSegment)
    .filter(Boolean);
  if (!segments.length) {
    throw new WebsiteBuilderError(
      "website_page_slug_invalid",
      "Page path is required.",
    );
  }
  const slug = `/${segments.join("/")}`;
  if (slug.length > PAGE_SLUG_LIMIT) {
    throw new WebsiteBuilderError(
      "website_page_slug_too_long",
      `Page paths may be at most ${PAGE_SLUG_LIMIT} characters.`,
    );
  }
  return slug;
}

export function normalizeWebsiteProjectCreate(body = {}) {
  return {
    name: requiredName(body.name, "Project name", PROJECT_NAME_LIMIT),
    kind: projectKind(body.kind),
  };
}

export function normalizeWebsiteProjectUpdate(body = {}) {
  const update = {
    expected_version: requiredVersion(body.expected_version),
    name: body.name === undefined
      ? undefined
      : requiredName(body.name, "Project name", PROJECT_NAME_LIMIT),
    lifecycle_status: body.lifecycle_status === undefined
      ? undefined
      : lifecycleStatus(body.lifecycle_status),
    theme: body.theme === undefined
      ? undefined
      : normalizeWebsiteProjectTheme(body.theme),
    navigation: body.navigation === undefined
      ? undefined
      : normalizeWebsiteProjectNavigation(body.navigation),
  };
  if (
    update.name === undefined &&
    update.lifecycle_status === undefined &&
    update.theme === undefined &&
    update.navigation === undefined
  ) {
    throw new WebsiteBuilderError(
      "website_project_update_empty",
      "Change the project name or lifecycle status before saving.",
    );
  }
  return update;
}

export function pageKindForProject(kind) {
  if (kind === "funnel") return "funnel_step";
  if (kind === "landing_page") return "landing";
  return "standard";
}

export function starterPageForProject({ kind, projectName }) {
  const name = kind === "funnel" ? "Step 1" : kind === "landing_page" ? "Landing" : "Home";
  const slug = kind === "funnel" ? "/step-1" : "/";
  return {
    name,
    slug,
    page_kind: pageKindForProject(kind),
    content: {
      schema_version: 1,
      blocks: [
        {
          id: randomUUID(),
          type: "hero",
          data: {
            heading: projectName,
            body: "Tell visitors what makes your company the right choice.",
          },
        },
      ],
    },
    seo: normalizeWebsitePageSeo({ title: projectName }),
  };
}

export function normalizeWebsitePageCreate(body = {}, kind = "website") {
  const name = requiredName(body.name, "Page name", PAGE_NAME_LIMIT);
  return {
    name,
    slug: normalizeWebsiteSlug(body.slug, name),
    page_kind: pageKindForProject(projectKind(kind)),
    expected_project_version: requiredVersion(
      body.expected_project_version,
      "expected_project_version",
    ),
  };
}

export function normalizeWebsitePageUpdate(body = {}) {
  const update = {
    expected_version: requiredVersion(body.expected_version),
    expected_project_version: requiredVersion(
      body.expected_project_version,
      "expected_project_version",
    ),
    name: body.name === undefined
      ? undefined
      : requiredName(body.name, "Page name", PAGE_NAME_LIMIT),
    slug: body.slug === undefined ? undefined : normalizeWebsiteSlug(body.slug),
    lifecycle_status: body.lifecycle_status === undefined
      ? undefined
      : lifecycleStatus(body.lifecycle_status),
    is_home: body.is_home === undefined ? undefined : body.is_home,
    content: body.content === undefined ? undefined : normalizeWebsitePageContent(body.content),
    seo: body.seo === undefined ? undefined : normalizeWebsitePageSeo(body.seo),
  };
  if (update.is_home !== undefined && typeof update.is_home !== "boolean") {
    throw new WebsiteBuilderError(
      "website_page_home_invalid",
      "Home/entry selection must be true or false.",
    );
  }
  if (
    update.name === undefined &&
    update.slug === undefined &&
    update.lifecycle_status === undefined &&
    update.is_home === undefined &&
    update.content === undefined &&
    update.seo === undefined
  ) {
    throw new WebsiteBuilderError(
      "website_page_update_empty",
      "Change the page before saving.",
    );
  }
  return update;
}

export function normalizeWebsitePageReorder(body = {}) {
  const targetIndex = typeof body.target_index === "string" && /^\d+$/.test(body.target_index.trim())
    ? Number(body.target_index.trim())
    : body.target_index;
  if (!Number.isSafeInteger(targetIndex) || targetIndex < 0 || targetIndex >= MAX_PAGES_PER_PROJECT) {
    throw new WebsiteBuilderError(
      "website_page_position_invalid",
      "Page position is invalid.",
    );
  }
  return {
    target_index: targetIndex,
    expected_project_version: requiredVersion(
      body.expected_project_version,
      "expected_project_version",
    ),
  };
}

function timestamp(value) {
  if (!value) return null;
  const parsed = value instanceof Date ? value : new Date(value);
  return Number.isFinite(parsed.getTime()) ? parsed.toISOString() : null;
}

function exactNumber(value) {
  const number = Number(value);
  return Number.isSafeInteger(number) ? number : 0;
}

function projectPayload(row) {
  return {
    id: String(row.id),
    name: String(row.name),
    kind: row.kind,
    lifecycle_status: row.lifecycle_status,
    theme: websiteProjectThemePayload(row.theme),
    navigation: websiteProjectNavigationPayload(row.navigation),
    version: exactNumber(row.version),
    active_page_count: exactNumber(row.active_page_count),
    archived_page_count: exactNumber(row.archived_page_count),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function pagePayload(row) {
  return {
    id: String(row.id),
    project_id: String(row.project_id),
    name: String(row.name),
    slug: String(row.slug),
    page_kind: row.page_kind,
    lifecycle_status: row.lifecycle_status,
    is_home: row.is_home === true,
    sort_order: exactNumber(row.sort_order),
    content: row.content && typeof row.content === "object" ? row.content : { schema_version: 1, blocks: [] },
    seo: websitePageSeoPayload(row.seo),
    version: exactNumber(row.version),
    created_at: timestamp(row.created_at),
    updated_at: timestamp(row.updated_at),
    archived_at: timestamp(row.archived_at),
  };
}

function projectAuditSnapshot(row) {
  return row ? {
    id: String(row.id),
    name: row.name,
    kind: row.kind,
    lifecycle_status: row.lifecycle_status,
    theme: websiteProjectThemePayload(row.theme),
    navigation: websiteProjectNavigationPayload(row.navigation),
    version: exactNumber(row.version),
  } : null;
}

function pageAuditSnapshot(row) {
  const content = row?.content && typeof row.content === "object" ? row.content : null;
  return row ? {
    id: String(row.id),
    project_id: String(row.project_id),
    name: row.name,
    slug: row.slug,
    page_kind: row.page_kind,
    lifecycle_status: row.lifecycle_status,
    is_home: row.is_home === true,
    sort_order: exactNumber(row.sort_order),
    content_schema_version: exactNumber(content?.schema_version),
    content_block_count: Array.isArray(content?.blocks) ? content.blocks.length : 0,
    seo: websitePageSeoPayload(row.seo),
    version: exactNumber(row.version),
  } : null;
}

async function appendAudit(client, { companyId, projectId, pageId = null, actorUserId, action, before = null, after = null }) {
  await client.query(
    `INSERT INTO website_builder_audit (
       company_id, project_id, page_id, actor_user_id, action, before_state, after_state
     ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb)`,
    [
      companyId,
      projectId,
      pageId,
      actorUserId,
      action,
      before == null ? null : JSON.stringify(before),
      after == null ? null : JSON.stringify(after),
    ],
  );
}

async function loadProject(client, companyId, projectId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_projects
      WHERE id::text = $1 AND company_id = $2${lock ? " FOR UPDATE" : ""}`,
    [projectId, companyId],
  );
  if (!rows[0]) {
    throw new WebsiteBuilderError(
      "website_project_not_found",
      "Website project was not found.",
      404,
    );
  }
  return rows[0];
}

async function loadPage(client, companyId, projectId, pageId, lock = false) {
  const { rows } = await client.query(
    `SELECT * FROM website_pages
      WHERE id::text = $1 AND project_id::text = $2 AND company_id = $3${lock ? " FOR UPDATE" : ""}`,
    [pageId, projectId, companyId],
  );
  if (!rows[0]) {
    throw new WebsiteBuilderError(
      "website_page_not_found",
      "Website page was not found.",
      404,
    );
  }
  return rows[0];
}

function requireCompany(req) {
  if (!req.companyId) {
    throw new WebsiteBuilderError(
      "company_required",
      "Website Builder requires a company workspace.",
      400,
    );
  }
  return req.companyId;
}

function assertVersion(row, expected, subject) {
  if (exactNumber(row.version) !== expected) {
    throw new WebsiteBuilderError(
      `website_${subject}_stale`,
      `This ${subject} changed after it was loaded. Refresh before saving again.`,
      409,
      { current_version: exactNumber(row.version) },
    );
  }
}

function sendWebsiteBuilderError(res, error, fallbackCode) {
  if (error instanceof WebsiteBuilderError || error?.statusCode) {
    return res.status(error.statusCode || 400).json({
      error: error.code || fallbackCode,
      message: error.message,
      current_version: error.current_version,
    });
  }
  if (error?.code === "23505") {
    return res.status(409).json({
      error: "website_slug_conflict",
      message: "That active page path is already used in this project.",
    });
  }
  console.error("[website-builder]", fallbackCode, {
    code: error?.code,
    message: error?.message,
  });
  return res.status(500).json({
    error: fallbackCode,
    message: "Website Builder could not complete that request.",
  });
}

export async function installWebsiteBuilderSchema(pool) {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS website_projects (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      kind TEXT NOT NULL CHECK (kind IN ('website', 'landing_page', 'funnel')),
      lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_status IN ('draft', 'archived')),
      theme JSONB NOT NULL DEFAULT '{}'::jsonb,
      navigation JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, company_id),
      CHECK (char_length(name) BETWEEN 1 AND ${PROJECT_NAME_LIMIT}),
      CHECK (jsonb_typeof(theme) = 'object'),
      CHECK (octet_length(theme::text) <= 8192),
      CHECK (jsonb_typeof(navigation) = 'object'),
      CHECK (octet_length(navigation::text) <= 32768)
    );
    ALTER TABLE website_projects
      ADD COLUMN IF NOT EXISTS theme JSONB NOT NULL DEFAULT '{}'::jsonb;
    ALTER TABLE website_projects
      ADD COLUMN IF NOT EXISTS navigation JSONB NOT NULL DEFAULT '{}'::jsonb;
    CREATE INDEX IF NOT EXISTS website_projects_company_status_updated_idx
      ON website_projects(company_id, lifecycle_status, updated_at DESC);

    CREATE TABLE IF NOT EXISTS website_pages (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID NOT NULL,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      page_kind TEXT NOT NULL CHECK (page_kind IN ('standard', 'landing', 'funnel_step')),
      lifecycle_status TEXT NOT NULL DEFAULT 'draft' CHECK (lifecycle_status IN ('draft', 'archived')),
      is_home BOOLEAN NOT NULL DEFAULT false,
      sort_order INTEGER NOT NULL DEFAULT 0 CHECK (sort_order >= 0),
      content JSONB NOT NULL DEFAULT '{"schema_version":1,"blocks":[]}'::jsonb,
      seo JSONB NOT NULL DEFAULT '{}'::jsonb,
      version INTEGER NOT NULL DEFAULT 1 CHECK (version > 0),
      created_by UUID REFERENCES users(id) ON DELETE SET NULL,
      updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      archived_at TIMESTAMPTZ,
      UNIQUE(id, project_id, company_id),
      FOREIGN KEY(project_id, company_id) REFERENCES website_projects(id, company_id) ON DELETE CASCADE,
      CHECK (char_length(name) BETWEEN 1 AND ${PAGE_NAME_LIMIT}),
      CHECK (char_length(slug) BETWEEN 1 AND ${PAGE_SLUG_LIMIT}),
      CHECK (jsonb_typeof(content) = 'object'),
      CHECK (jsonb_typeof(seo) = 'object'),
      CHECK (octet_length(content::text) <= 262144),
      CHECK (octet_length(seo::text) <= 32768)
    );
    CREATE INDEX IF NOT EXISTS website_pages_project_status_order_idx
      ON website_pages(company_id, project_id, lifecycle_status, sort_order, created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS website_pages_active_slug_uidx
      ON website_pages(project_id, lower(slug)) WHERE archived_at IS NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS website_pages_active_home_uidx
      ON website_pages(project_id) WHERE is_home AND archived_at IS NULL;

    CREATE TABLE IF NOT EXISTS website_builder_audit (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      company_id UUID NOT NULL REFERENCES companies(id) ON DELETE CASCADE,
      project_id UUID REFERENCES website_projects(id) ON DELETE SET NULL,
      page_id UUID REFERENCES website_pages(id) ON DELETE SET NULL,
      actor_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
      action TEXT NOT NULL,
      before_state JSONB,
      after_state JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS website_builder_audit_company_project_idx
      ON website_builder_audit(company_id, project_id, created_at DESC);
  `);
}

export async function installWebsiteBuilderSystem({ app, pool, authRequired, requireView, requireManage }) {
  await installWebsiteBuilderSchema(pool);

  app.get("/api/website-builder/projects", authRequired, requireView, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      const status = req.query.status === "archived" ? "archived" : req.query.status === "all" ? "all" : "draft";
      const values = [companyId];
      const where = status === "all" ? "" : " AND p.lifecycle_status = $2";
      if (status !== "all") values.push(status);
      const { rows } = await pool.query(
        `SELECT p.*,
                COUNT(pg.id) FILTER (WHERE pg.archived_at IS NULL)::int AS active_page_count,
                COUNT(pg.id) FILTER (WHERE pg.archived_at IS NOT NULL)::int AS archived_page_count
           FROM website_projects p
           LEFT JOIN website_pages pg ON pg.project_id = p.id AND pg.company_id = p.company_id
          WHERE p.company_id = $1${where}
          GROUP BY p.id
          ORDER BY (p.lifecycle_status = 'archived') ASC, p.updated_at DESC, lower(p.name) ASC
          LIMIT ${MAX_PROJECTS_PER_COMPANY}`,
        values,
      );
      res.json({ projects: rows.map(projectPayload) });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_projects_load_failed");
    }
  });

  app.post("/api/website-builder/projects", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteProjectCreate(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_project_create_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const count = await client.query(
        `SELECT COUNT(*)::int AS count FROM website_projects WHERE company_id = $1`,
        [req.companyId],
      );
      if (exactNumber(count.rows[0]?.count) >= MAX_PROJECTS_PER_COMPANY) {
        throw new WebsiteBuilderError(
          "website_project_limit_reached",
          `A company may have up to ${MAX_PROJECTS_PER_COMPANY} Website Builder projects.`,
          409,
        );
      }
      const projectId = randomUUID();
      const pageId = randomUUID();
      const project = (await client.query(
        `INSERT INTO website_projects (
           id, company_id, name, kind, created_by, updated_by
         ) VALUES ($1,$2,$3,$4,$5,$5)
         RETURNING *`,
        [projectId, req.companyId, input.name, input.kind, req.userId],
      )).rows[0];
      const starter = starterPageForProject({ kind: input.kind, projectName: input.name });
      const page = (await client.query(
        `INSERT INTO website_pages (
           id, company_id, project_id, name, slug, page_kind, is_home,
           sort_order, content, seo, created_by, updated_by
         ) VALUES ($1,$2,$3,$4,$5,$6,true,0,$7::jsonb,$8::jsonb,$9,$9)
         RETURNING *`,
        [
          pageId,
          req.companyId,
          projectId,
          starter.name,
          starter.slug,
          starter.page_kind,
          JSON.stringify(starter.content),
          JSON.stringify(starter.seo),
          req.userId,
        ],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId,
        pageId,
        actorUserId: req.userId,
        action: "project.created",
        after: { project: projectAuditSnapshot(project), starter_page: pageAuditSnapshot(page) },
      });
      await client.query("COMMIT");
      res.status(201).json({
        project: projectPayload({ ...project, active_page_count: 1, archived_page_count: 0 }),
        pages: [pagePayload(page)],
      });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_project_create_failed");
    } finally {
      client.release();
    }
  });

  app.get("/api/website-builder/projects/:projectId", authRequired, requireView, async (req, res) => {
    try {
      const companyId = requireCompany(req);
      const project = await loadProject(pool, companyId, req.params.projectId);
      const { rows } = await pool.query(
        `SELECT * FROM website_pages
          WHERE company_id = $1 AND project_id = $2
          ORDER BY (archived_at IS NOT NULL) ASC, sort_order ASC, created_at ASC`,
        [companyId, project.id],
      );
      const activeCount = rows.filter((row) => !row.archived_at).length;
      res.json({
        project: projectPayload({
          ...project,
          active_page_count: activeCount,
          archived_page_count: rows.length - activeCount,
        }),
        pages: rows.map(pagePayload),
      });
    } catch (error) {
      sendWebsiteBuilderError(res, error, "website_project_load_failed");
    }
  });

  app.patch("/api/website-builder/projects/:projectId", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsiteProjectUpdate(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_project_update_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const current = await loadProject(client, req.companyId, req.params.projectId, true);
      assertVersion(current, input.expected_version, "project");
      if (
        current.lifecycle_status === "archived" &&
        (input.name !== undefined || input.theme !== undefined || input.navigation !== undefined) &&
        input.lifecycle_status !== "draft"
      ) {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before changing its settings.",
          409,
        );
      }
      const nextName = input.name ?? current.name;
      const nextStatus = input.lifecycle_status ?? current.lifecycle_status;
      const nextTheme = input.theme ?? websiteProjectThemePayload(current.theme);
      const nextNavigation = input.navigation ?? websiteProjectNavigationPayload(current.navigation);
      if (input.navigation?.mode === "custom") {
        const pageIds = input.navigation.items.map((item) => item.page_id);
        if (pageIds.length) {
          const { rows } = await client.query(
            `SELECT id::text AS id FROM website_pages
              WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL
                AND id = ANY($3::uuid[])`,
            [req.companyId, current.id, pageIds],
          );
          if (rows.length !== pageIds.length) {
            throw new WebsiteBuilderError(
              "website_project_navigation_page_invalid",
              "Custom navigation may include only active pages from this project.",
              409,
            );
          }
        }
      }
      const themeUnchanged = JSON.stringify(nextTheme) === JSON.stringify(websiteProjectThemePayload(current.theme));
      const navigationUnchanged = JSON.stringify(nextNavigation) === JSON.stringify(websiteProjectNavigationPayload(current.navigation));
      if (nextName === current.name && nextStatus === current.lifecycle_status && themeUnchanged && navigationUnchanged) {
        await client.query("COMMIT");
        return res.json({ project: projectPayload(current) });
      }
      const updated = (await client.query(
        `UPDATE website_projects
            SET name = $3,
                lifecycle_status = $4,
                theme = $5::jsonb,
                navigation = $6::jsonb,
                archived_at = CASE WHEN $4 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
                updated_by = $7,
                updated_at = now(),
                version = version + 1
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [current.id, req.companyId, nextName, nextStatus, JSON.stringify(nextTheme), JSON.stringify(nextNavigation), req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId: current.id,
        actorUserId: req.userId,
        action: nextStatus !== current.lifecycle_status
          ? `project.${nextStatus}`
          : !navigationUnchanged && nextName === current.name && themeUnchanged
            ? "project.navigation_updated"
            : !themeUnchanged && nextName === current.name && navigationUnchanged
              ? "project.theme_updated"
              : "project.updated",
        before: projectAuditSnapshot(current),
        after: projectAuditSnapshot(updated),
      });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updated) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_project_update_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/website-builder/projects/:projectId/pages", authRequired, requireManage, async (req, res) => {
    let companyId;
    try {
      companyId = requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_page_create_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before adding pages.",
          409,
        );
      }
      const input = normalizeWebsitePageCreate(req.body, project.kind);
      assertVersion(project, input.expected_project_version, "project");
      const count = await client.query(
        `SELECT COUNT(*)::int AS count,
                COALESCE(MAX(sort_order) FILTER (WHERE archived_at IS NULL), -1)::int AS maximum
           FROM website_pages WHERE company_id = $1 AND project_id = $2`,
        [companyId, project.id],
      );
      if (exactNumber(count.rows[0]?.count) >= MAX_PAGES_PER_PROJECT) {
        throw new WebsiteBuilderError(
          "website_page_limit_reached",
          `A project may have up to ${MAX_PAGES_PER_PROJECT} total pages.`,
          409,
        );
      }
      const pageId = randomUUID();
      const content = {
        schema_version: 1,
        blocks: [{
          id: randomUUID(),
          type: "hero",
          data: { heading: input.name, body: "Add the details visitors need to take the next step." },
        }],
      };
      const page = (await client.query(
        `INSERT INTO website_pages (
           id, company_id, project_id, name, slug, page_kind, sort_order,
           content, seo, created_by, updated_by
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb,$9::jsonb,$10,$10)
         RETURNING *`,
        [
          pageId,
          companyId,
          project.id,
          input.name,
          input.slug,
          input.page_kind,
          exactNumber(count.rows[0]?.maximum) + 1,
          JSON.stringify(content),
          JSON.stringify(normalizeWebsitePageSeo({ title: input.name })),
          req.userId,
        ],
      )).rows[0];
      const updatedProject = (await client.query(
        `UPDATE website_projects
            SET version = version + 1, updated_at = now(), updated_by = $3
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [project.id, companyId, req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId,
        projectId: project.id,
        pageId,
        actorUserId: req.userId,
        action: "page.created",
        after: pageAuditSnapshot(page),
      });
      await client.query("COMMIT");
      res.status(201).json({ project: projectPayload(updatedProject), page: pagePayload(page) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_create_failed");
    } finally {
      client.release();
    }
  });

  app.patch("/api/website-builder/projects/:projectId/pages/:pageId", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePageUpdate(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_page_update_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before changing its pages.",
          409,
        );
      }
      assertVersion(project, input.expected_project_version, "project");
      const current = await loadPage(client, req.companyId, project.id, req.params.pageId, true);
      assertVersion(current, input.expected_version, "page");
      const nextName = input.name ?? current.name;
      const nextSlug = input.slug ?? current.slug;
      const nextStatus = input.lifecycle_status ?? current.lifecycle_status;
      const nextContent = input.content ?? current.content;
      const nextSeo = input.seo ?? current.seo;
      let nextHome = input.is_home ?? current.is_home;
      let replacementHomeId = null;

      if (nextStatus === "archived") nextHome = false;
      if (current.is_home && nextStatus !== "archived" && nextHome === false) {
        throw new WebsiteBuilderError(
          "website_home_required",
          "Choose another home/entry page before removing this one.",
          409,
        );
      }
      if (current.lifecycle_status !== "archived" && nextStatus === "archived") {
        const siblings = (await client.query(
          `SELECT * FROM website_pages
            WHERE company_id = $1 AND project_id = $2 AND id <> $3 AND archived_at IS NULL
            ORDER BY sort_order ASC, created_at ASC
            FOR UPDATE`,
          [req.companyId, project.id, current.id],
        )).rows;
        if (!siblings.length) {
          throw new WebsiteBuilderError(
            "website_last_page_required",
            "A project must keep at least one active page.",
            409,
          );
        }
        if (current.is_home) {
          replacementHomeId = siblings[0].id;
        }
      }
      if (nextHome && nextStatus !== "archived") {
        await client.query(
          `UPDATE website_pages
              SET is_home = false, version = version + 1, updated_at = now(), updated_by = $4
            WHERE project_id = $1 AND company_id = $2 AND id <> $3 AND is_home = true AND archived_at IS NULL`,
          [project.id, req.companyId, current.id, req.userId],
        );
      }
      const unchanged =
        nextName === current.name &&
        nextSlug === current.slug &&
        nextStatus === current.lifecycle_status &&
        nextHome === current.is_home &&
        JSON.stringify(nextContent) === JSON.stringify(current.content) &&
        JSON.stringify(websitePageSeoPayload(nextSeo)) === JSON.stringify(websitePageSeoPayload(current.seo));
      if (unchanged) {
        await client.query("COMMIT");
        return res.json({ project: projectPayload(project), page: pagePayload(current) });
      }
      const page = (await client.query(
        `UPDATE website_pages
            SET name = $4,
                slug = $5,
                lifecycle_status = $6,
                is_home = $7,
                content = $8::jsonb,
                seo = $9::jsonb,
                archived_at = CASE WHEN $6 = 'archived' THEN COALESCE(archived_at, now()) ELSE NULL END,
                updated_by = $10,
                updated_at = now(),
                version = version + 1
          WHERE id = $1 AND project_id = $2 AND company_id = $3
          RETURNING *`,
        [current.id, project.id, req.companyId, nextName, nextSlug, nextStatus, nextHome, JSON.stringify(nextContent), JSON.stringify(websitePageSeoPayload(nextSeo)), req.userId],
      )).rows[0];
      if (replacementHomeId) {
        await client.query(
          `UPDATE website_pages
              SET is_home = true, version = version + 1, updated_at = now(), updated_by = $4
            WHERE id = $1 AND project_id = $2 AND company_id = $3`,
          [replacementHomeId, project.id, req.companyId, req.userId],
        );
      }
      const nextProjectNavigation = websiteProjectNavigationPayload(project.navigation);
      if (nextStatus === "archived" && nextProjectNavigation.mode === "custom") {
        nextProjectNavigation.items = nextProjectNavigation.items.filter(
          (item) => item.page_id !== String(current.id),
        );
      }
      const updatedProject = (await client.query(
        `UPDATE website_projects
            SET navigation = $3::jsonb, version = version + 1, updated_at = now(), updated_by = $4
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [project.id, req.companyId, JSON.stringify(nextProjectNavigation), req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId: project.id,
        pageId: current.id,
        actorUserId: req.userId,
        action: nextStatus !== current.lifecycle_status
          ? `page.${nextStatus}`
          : input.content !== undefined
            ? "page.content_updated"
            : input.seo !== undefined
              ? "page.seo_updated"
              : "page.updated",
        before: pageAuditSnapshot(current),
        after: pageAuditSnapshot(page),
      });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updatedProject), page: pagePayload(page) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_update_failed");
    } finally {
      client.release();
    }
  });

  app.post("/api/website-builder/projects/:projectId/pages/:pageId/reorder", authRequired, requireManage, async (req, res) => {
    let input;
    try {
      input = normalizeWebsitePageReorder(req.body);
      requireCompany(req);
    } catch (error) {
      return sendWebsiteBuilderError(res, error, "website_page_reorder_failed");
    }
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const project = await loadProject(client, req.companyId, req.params.projectId, true);
      if (project.lifecycle_status === "archived") {
        throw new WebsiteBuilderError(
          "website_project_archived",
          "Restore the project before reordering pages.",
          409,
        );
      }
      assertVersion(project, input.expected_project_version, "project");
      const pages = (await client.query(
        `SELECT * FROM website_pages
          WHERE company_id = $1 AND project_id = $2 AND archived_at IS NULL
          ORDER BY sort_order ASC, created_at ASC
          FOR UPDATE`,
        [req.companyId, project.id],
      )).rows;
      const currentIndex = pages.findIndex((page) => String(page.id) === req.params.pageId);
      if (currentIndex < 0) {
        throw new WebsiteBuilderError(
          "website_page_not_found",
          "Active website page was not found.",
          404,
        );
      }
      const targetIndex = Math.min(input.target_index, pages.length - 1);
      if (targetIndex === currentIndex) {
        await client.query("COMMIT");
        return res.json({ project: projectPayload(project), pages: pages.map(pagePayload) });
      }
      const [moved] = pages.splice(currentIndex, 1);
      pages.splice(targetIndex, 0, moved);
      for (let index = 0; index < pages.length; index += 1) {
        if (exactNumber(pages[index].sort_order) === index) continue;
        pages[index] = (await client.query(
          `UPDATE website_pages
              SET sort_order = $4, version = version + 1, updated_at = now(), updated_by = $5
            WHERE id = $1 AND project_id = $2 AND company_id = $3
            RETURNING *`,
          [pages[index].id, project.id, req.companyId, index, req.userId],
        )).rows[0];
      }
      const updatedProject = (await client.query(
        `UPDATE website_projects
            SET version = version + 1, updated_at = now(), updated_by = $3
          WHERE id = $1 AND company_id = $2
          RETURNING *`,
        [project.id, req.companyId, req.userId],
      )).rows[0];
      await appendAudit(client, {
        companyId: req.companyId,
        projectId: project.id,
        pageId: moved.id,
        actorUserId: req.userId,
        action: "page.reordered",
        before: { index: currentIndex },
        after: { index: targetIndex },
      });
      await client.query("COMMIT");
      res.json({ project: projectPayload(updatedProject), pages: pages.map(pagePayload) });
    } catch (error) {
      await client.query("ROLLBACK").catch(() => {});
      sendWebsiteBuilderError(res, error, "website_page_reorder_failed");
    } finally {
      client.release();
    }
  });
}
